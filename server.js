import express from "express";
import crypto from "crypto";

const app = express();

/* =========================
RAW BODY (for HMAC)
========================= */
app.use(express.json({
limit: "1mb",
verify: (req, res, buf) => { req.rawBody = buf; }
}));

const {
SHOPIFY_SHOP,
SHOPIFY_ADMIN_TOKEN,
SHOPIFY_API_SECRET,
SHOPIFY_API_VERSION = "2025-10",
PRESENTMENT_CURRENCY = "GBP",
PORT = 3000,

ALLOWED_ORIGIN,
FRONTEND_SHARED_SECRET,

// Optional: anchor variant for checkout image
ANCHOR_VARIANT_GID
} = process.env;

if (!SHOPIFY_SHOP || !SHOPIFY_ADMIN_TOKEN || !SHOPIFY_API_SECRET) {
console.error("Missing Shopify env vars");
process.exit(1);
}
if (!ALLOWED_ORIGIN || !FRONTEND_SHARED_SECRET) {
console.error("Missing frontend security env vars");
process.exit(1);
}

/* =========================
CORS
========================= */
function setCors(res, origin) {
res.setHeader("Access-Control-Allow-Origin", origin);
res.setHeader("Vary", "Origin");
res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
res.setHeader("Access-Control-Allow-Headers", "Content-Type,X-RG-Timestamp,X-RG-Signature");
}

app.options("/checkout", (req, res) => {
const origin = req.headers.origin || "";
if (origin === ALLOWED_ORIGIN) setCors(res, origin);
return res.status(204).end();
});

/* =========================
PRICING (INC VAT)
========================= */
const PRICING = {
BASE_RATE: 150,
MIN_PRICE: 72.07,
MM_FACTOR: 0.002
};

function calcUnitPriceIncVat(unit) {
const { outerGlass, innerGlass, selfCleaning, widthMm, heightMm } = unit;
if (!widthMm || !heightMm) return 0;

if (
outerGlass === "4mm Clear" &&
innerGlass === "4mm Clear" &&
selfCleaning === "No"
) {
const areaM2 = (widthMm * heightMm) / 1_000_000;
const areaCost = areaM2 * PRICING.BASE_RATE;
const mmAdj = (widthMm + heightMm) * PRICING.MM_FACTOR;
return Math.max(PRICING.MIN_PRICE, areaCost) + mmAdj;
}

return 0;
}

/* =========================
RULES
========================= */
function clampDims(w, h) {
const min = 150, maxW = 2000, maxH = 3000;
return {
w: Math.min(maxW, Math.max(min, w)),
h: Math.min(maxH, Math.max(min, h))
};
}

function applyAreaRule(unit) {
const area = (unit.widthMm * unit.heightMm) / 1_000_000;
if (
area >= 2.5 &&
unit.outerGlass === "4mm Clear" &&
unit.innerGlass === "4mm Clear"
) {
return {
...unit,
outerGlass: "6mm Clear",
innerGlass: "6mm Clear",
_areaUpgradeApplied: true
};
}
return { ...unit, _areaUpgradeApplied: false };
}

function normalizeUnit(raw) {
const { w, h } = clampDims(Number(raw.widthMm), Number(raw.heightMm));
return applyAreaRule({
qty: Math.min(10, Math.max(1, Number(raw.qty) || 1)),
outerGlass: String(raw.outerGlass),
innerGlass: String(raw.innerGlass),
cavityWidth: String(raw.cavityWidth),
selfCleaning: String(raw.selfCleaning),
spacer: String(raw.spacer),
widthMm: w,
heightMm: h,
toughened: "Yes"
});
}

/* =========================
HMAC VERIFICATION
========================= */
function timingSafeEqualHex(a, b) {
const ab = Buffer.from(a, "hex");
const bb = Buffer.from(b, "hex");
if (ab.length !== bb.length) return false;
return crypto.timingSafeEqual(ab, bb);
}

function verifyFrontendSignature(req) {
const ts = String(req.headers["x-rg-timestamp"] || "");
const sig = String(req.headers["x-rg-signature"] || "");
if (!ts || !sig) return false;

const raw = req.rawBody.toString("utf8");
const payload = `${ts}.${raw}`;
const digest = crypto.createHmac("sha256", FRONTEND_SHARED_SECRET)
.update(payload)
.digest("hex");

return timingSafeEqualHex(sig, digest);
}

/* =========================
SHOPIFY GRAPHQL
========================= */
async function shopifyGraphQL(query, variables) {
const res = await fetch(
`https://${SHOPIFY_SHOP}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
{
method: "POST",
headers: {
"Content-Type": "application/json",
"X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN
},
body: JSON.stringify({ query, variables })
}
);

const json = await res.json();
if (!res.ok || json.errors) throw new Error(JSON.stringify(json));
return json.data;
}

/* =========================
CHECKOUT
========================= */
app.post("/checkout", async (req, res) => {
try {
const origin = req.headers.origin || "";
if (origin !== ALLOWED_ORIGIN) return res.status(403).json({ error: "Forbidden" });
setCors(res, origin);

if (!verifyFrontendSignature(req)) {
return res.status(401).json({ error: "Invalid signature" });
}

const unitsRaw = req.body?.units;
if (!Array.isArray(unitsRaw) || !unitsRaw.length) {
return res.status(400).json({ error: "Missing units" });
}

const units = unitsRaw.map(normalizeUnit);

let grandTotal = 0;
for (const u of units) {
const unitPrice = calcUnitPriceIncVat(u);
u._unitPriceIncVat = unitPrice;
grandTotal += unitPrice * u.qty;
}

if (grandTotal <= 0) {
return res.status(422).json({ error: "Unpriced configuration" });
}

// ✅ NEW: total number of units INCLUDING qty
const totalUnits = units.reduce((sum, u) => sum + (Number(u.qty) || 0), 0);

const mutation = `
mutation draftOrderCreate($input: DraftOrderInput!) {
draftOrderCreate(input: $input) {
draftOrder { id invoiceUrl }
userErrors { message }
}
}
`;

const input = {
presentmentCurrencyCode: PRESENTMENT_CURRENCY,
lineItems: [{
title: "Bespoke Double Glazed Units",
quantity: 1,
requiresShipping: true,
taxable: true,
variantId: ANCHOR_VARIANT_GID || null,
priceOverride: {
amount: grandTotal.toFixed(2),
currencyCode: PRESENTMENT_CURRENCY
},
customAttributes: [
// ✅ CHANGED: label + value logic
{ key: "No. of Units", value: String(totalUnits) },
{ key: "Grand Total (inc VAT)", value: `£${grandTotal.toFixed(2)}` }
]
}]
};

const data = await shopifyGraphQL(mutation, { input });
const draft = data.draftOrderCreate.draftOrder;

return res.json({
invoiceUrl: draft.invoiceUrl,
grandTotal: Number(grandTotal.toFixed(2))
});

} catch (err) {
console.error(err);
return res.status(500).json({ error: "Server error" });
}
});

app.get("/health", (_, res) => res.json({ ok: true }));

app.listen(PORT, () =>
console.log(`RightGlaze draft order app listening on ${PORT}`)
);
