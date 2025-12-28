import express from "express";
import crypto from "crypto";

const app = express();

/* =========================
CAPTURE RAW BODY FOR HMAC
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
FRONTEND_SHARED_SECRET
} = process.env;

if (!SHOPIFY_SHOP || !SHOPIFY_ADMIN_TOKEN || !SHOPIFY_API_SECRET) {
console.error("Missing Shopify credentials");
process.exit(1);
}
if (!ALLOWED_ORIGIN || !FRONTEND_SHARED_SECRET) {
console.error("Missing ALLOWED_ORIGIN or FRONTEND_SHARED_SECRET");
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
if (req.headers.origin === ALLOWED_ORIGIN) setCors(res, req.headers.origin);
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

if (outerGlass === "4mm Clear" && innerGlass === "4mm Clear" && selfCleaning === "No") {
const area = (widthMm * heightMm) / 1_000_000;
return Math.max(PRICING.MIN_PRICE, area * PRICING.BASE_RATE)
+ (widthMm + heightMm) * PRICING.MM_FACTOR;
}
return 0;
}

/* =========================
RULES
========================= */
function clampDims(w, h) {
return {
w: Math.min(2000, Math.max(150, w)),
h: Math.min(3000, Math.max(150, h))
};
}

function applyAreaRule(unit) {
const area = (unit.widthMm * unit.heightMm) / 1_000_000;
if (area >= 2.5 && unit.outerGlass === "4mm Clear" && unit.innerGlass === "4mm Clear") {
return { ...unit, outerGlass: "6mm Clear", innerGlass: "6mm Clear", _areaUpgrade: true };
}
return { ...unit, _areaUpgrade: false };
}

function normalizeUnit(raw) {
const { w, h } = clampDims(Number(raw.widthMm), Number(raw.heightMm));
return applyAreaRule({
qty: Math.min(10, Math.max(1, Number(raw.qty) || 1)),
outerGlass: String(raw.outerGlass),
innerGlass: String(raw.innerGlass),
cavityWidth: String(raw.cavityWidth),
selfCleaning: String(raw.selfCleaning || "No"),
spacer: String(raw.spacer),
widthMm: w,
heightMm: h,
toughened: "Yes"
});
}

/* =========================
SIGNATURE CHECK
========================= */
function verifySignature(req) {
const ts = req.headers["x-rg-timestamp"];
const sig = req.headers["x-rg-signature"];
if (!ts || !sig) return false;

const raw = req.rawBody?.toString("utf8") || "";
const expected = crypto.createHmac("sha256", FRONTEND_SHARED_SECRET)
.update(`${ts}.${raw}`)
.digest("hex");

return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
}

/* =========================
SHOPIFY GRAPHQL
========================= */
async function shopify(query, variables) {
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
FORMAT BREAKDOWN
========================= */
function formatBreakdown(units, total) {
const lines = ["RightGlaze Bespoke Units (inc VAT)", ""];
units.forEach((u, i) => {
lines.push(`Unit ${i + 1} × ${u.qty}`);
lines.push(`Outer: ${u.outerGlass}`);
lines.push(`Inner: ${u.innerGlass}`);
lines.push(`Cavity: ${u.cavityWidth}`);
lines.push(`Self-cleaning: ${u.selfCleaning}`);
lines.push(`Spacer: ${u.spacer}`);
lines.push(`Size: ${u.widthMm}mm × ${u.heightMm}mm`);
if (u._areaUpgrade) lines.push(`Note: Auto-upgraded to 6mm due to size`);
lines.push("");
});
lines.push(`ORDER TOTAL: £${total.toFixed(2)} (inc VAT)`);
return lines.join("\n");
}

/* =========================
CHECKOUT ENDPOINT
========================= */
app.post("/checkout", async (req, res) => {
try {
if (req.headers.origin !== ALLOWED_ORIGIN) return res.status(403).end();
setCors(res, req.headers.origin);

if (!verifySignature(req)) return res.status(401).end();

const rawUnits = req.body?.units;
if (!Array.isArray(rawUnits) || !rawUnits.length) {
return res.status(400).json({ error: "No units provided" });
}

const units = rawUnits.map(normalizeUnit);
let grandTotal = 0;

units.forEach(u => {
const price = calcUnitPriceIncVat(u);
u._unitPrice = price;
grandTotal += price * u.qty;
});

if (grandTotal <= 0) {
return res.status(422).json({ error: "Unpriced configuration" });
}

const mutation = `
mutation draftOrderCreate($input: DraftOrderInput!) {
draftOrderCreate(input: $input) {
draftOrder { invoiceUrl }
userErrors { message }
}
}
`;

const input = {
note: formatBreakdown(units, grandTotal),
presentmentCurrencyCode: PRESENTMENT_CURRENCY,
lineItems: [{
title: "Bespoke Double Glazed Units (Custom Order)",
quantity: 1,
requiresShipping: true,
taxable: false,
originalUnitPriceWithCurrency: {
amount: grandTotal.toFixed(2),
currencyCode: PRESENTMENT_CURRENCY
}
}]
};

const data = await shopify(mutation, { input });
const invoiceUrl = data.draftOrderCreate.draftOrder.invoiceUrl;

return res.json({ invoiceUrl, grandTotal });
} catch (err) {
console.error(err);
res.status(500).json({ error: "Server error" });
}
});

/* =========================
HEALTH
========================= */
app.get("/health", (_, res) => res.json({ ok: true }));

app.listen(PORT, () =>
console.log(`RightGlaze draft order app running on ${PORT}`)
);
