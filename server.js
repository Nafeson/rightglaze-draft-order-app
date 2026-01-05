import express from "express";
import crypto from "crypto";

const app = express();

/* =========================
RAW BODY (for HMAC)
========================= */
app.use(
express.json({
limit: "1mb",
verify: (req, res, buf) => {
req.rawBody = buf;
},
})
);

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
ANCHOR_VARIANT_GID,
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
res.setHeader(
"Access-Control-Allow-Headers",
"Content-Type,X-RG-Timestamp,X-RG-Signature"
);
}

app.options("/checkout", (req, res) => {
const origin = req.headers.origin || "";
if (origin === ALLOWED_ORIGIN) setCors(res, origin);
return res.status(204).end();
});

/* =========================
PRICING (INC VAT) — TIER TABLES
========================= */

/**
* Area bands are interpreted as:
* - < 0.5
* - 0.5–0.99
* - 1.0–1.49
* - 1.5–1.99
* - 2.0–2.5
* - 2.51–3.0
*
* NOTE: Your area upgrade rule may move 4/4 -> 6/6 at >= 2.5m²,
* so 4mm tables above 2.5 may never be used (which is fine).
*/

function areaBand(areaM2) {
if (areaM2 < 0.5) return "LT_0_5";
if (areaM2 < 1.0) return "0_5_TO_0_99";
if (areaM2 < 1.5) return "1_0_TO_1_49";
if (areaM2 < 2.0) return "1_5_TO_1_99";
if (areaM2 <= 2.5) return "2_0_TO_2_5";
// > 2.5 up to 3.0
return "2_51_TO_3_0";
}

const BASE_RATE_PER_M2 = {
"4mm Clear|4mm Clear": {
minPrice: 48.75,
rates: {
LT_0_5: 125,
"0_5_TO_0_99": 125,
"1_0_TO_1_49": 130,
"1_5_TO_1_99": 132,
"2_0_TO_2_5": 135,
// not provided for >2.5 (typically upgraded to 6/6 by rule)
"2_51_TO_3_0": null,
},
},

"4mm Clear|4mm Softcoat": {
minPrice: 48.75,
rates: {
LT_0_5: 130,
"0_5_TO_0_99": 130,
"1_0_TO_1_49": 135,
"1_5_TO_1_99": 138,
"2_0_TO_2_5": 145,
// not provided for >2.5 (typically upgraded to 6/6 by rule)
"2_51_TO_3_0": null,
},
},

"6mm Clear|6mm Clear": {
minPrice: 95.75,
rates: {
LT_0_5: 215,
"0_5_TO_0_99": 265,
"1_0_TO_1_49": 275,
"1_5_TO_1_99": 283,
"2_0_TO_2_5": 285,
"2_51_TO_3_0": 290,
},
},

"6mm Clear|6mm Softcoat": {
minPrice: 127.75,
rates: {
LT_0_5: 225,
"0_5_TO_0_99": 275,
"1_0_TO_1_49": 285,
"1_5_TO_1_99": 293,
"2_0_TO_2_5": 295,
"2_51_TO_3_0": 300,
},
},
};

const SELF_CLEANING_ADDON_PER_M2 = {
LT_0_5: 30,
"0_5_TO_0_99": 35,
"1_0_TO_1_49": 40,
"1_5_TO_1_99": 45,
"2_0_TO_2_5": 50,
"2_51_TO_3_0": 55,
};

function calcUnitPriceIncVat(unit) {
const { outerGlass, innerGlass, selfCleaning, widthMm, heightMm } = unit;
if (!Number.isFinite(widthMm) || !Number.isFinite(heightMm) || widthMm <= 0 || heightMm <= 0) return 0;

const areaM2 = (widthMm * heightMm) / 1_000_000;

const key = `${outerGlass}|${innerGlass}`;
const table = BASE_RATE_PER_M2[key];
if (!table) return 0;

const band = areaBand(areaM2);
const rate = table.rates[band];

// If no rate exists for this band, treat as unpriced
if (!Number.isFinite(rate)) return 0;

// Base = max(min price, area * rate)
let price = Math.max(table.minPrice, areaM2 * rate);

// Self-cleaning add-on per m² (on top of base)
if (String(selfCleaning || "").toLowerCase() === "yes") {
const scRate = SELF_CLEANING_ADDON_PER_M2[band];
if (Number.isFinite(scRate)) {
price += areaM2 * scRate;
}
}

return Number(price.toFixed(2));
}

/* =========================
RULES
========================= */

// Match your latest calculator constraints:
// - min 150mm
// - width absolute max 3000mm
// - height absolute max 1732mm
// - area max 3.0 m² (handled via dynamic messaging in frontend, but server clamps dims and can still price up to 3)
function clampDims(w, h) {
const min = 150;
const maxW = 3000;
const maxH = 1732;

const cw = Math.min(maxW, Math.max(min, w));
const ch = Math.min(maxH, Math.max(min, h));

return { w: cw, h: ch };
}

// Keep your existing upgrade rule (>= 2.5m² upgrades 4/4 to 6/6)
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
_areaUpgradeApplied: true,
};
}
return { ...unit, _areaUpgradeApplied: false };
}

function normalizeUnit(raw) {
const { w, h } = clampDims(Number(raw.widthMm), Number(raw.heightMm));
return applyAreaRule({
qty: Math.min(10, Math.max(1, Number(raw.qty) || 1)),
outerGlass: String(raw.outerGlass || ""),
innerGlass: String(raw.innerGlass || ""),
cavityWidth: String(raw.cavityWidth || ""),
selfCleaning: String(raw.selfCleaning || "No"),
spacer: String(raw.spacer || ""),
widthMm: w,
heightMm: h,
toughened: "Yes",
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
const digest = crypto
.createHmac("sha256", FRONTEND_SHARED_SECRET)
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
"X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
},
body: JSON.stringify({ query, variables }),
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

// round once at the end
grandTotal = Number(grandTotal.toFixed(2));

if (grandTotal <= 0) {
return res.status(422).json({ error: "Unpriced configuration" });
}

// ✅ total number of units INCLUDING qty
const totalUnits = units.reduce((sum, u) => sum + (Number(u.qty) || 0), 0);

const mutation = `
mutation draftOrderCreate($input: DraftOrderInput!) {
draftOrderCreate(input: $input) {
draftOrder { id invoiceUrl }
userErrors { message }
}
}
`;

// Build line item and only include variantId if you have it (avoids GraphQL fussiness)
const lineItem = {
title: "Bespoke Double Glazed Units",
quantity: 1,
requiresShipping: true,
taxable: true,
priceOverride: {
amount: grandTotal.toFixed(2),
currencyCode: PRESENTMENT_CURRENCY,
},
customAttributes: [
{ key: "No. of Units", value: String(totalUnits) },
{ key: "Grand Total (inc VAT)", value: `£${grandTotal.toFixed(2)}` },
],
};

if (ANCHOR_VARIANT_GID) {
lineItem.variantId = ANCHOR_VARIANT_GID;
}

const input = {
presentmentCurrencyCode: PRESENTMENT_CURRENCY,
lineItems: [lineItem],
};

const data = await shopifyGraphQL(mutation, { input });

const draft = data?.draftOrderCreate?.draftOrder;
const errs = data?.draftOrderCreate?.userErrors || [];
if (errs.length) {
return res.status(400).json({ error: "Draft order error", details: errs });
}
if (!draft?.invoiceUrl) {
return res.status(500).json({ error: "Draft created but invoiceUrl missing" });
}

return res.json({
invoiceUrl: draft.invoiceUrl,
grandTotal,
});
} catch (err) {
console.error(err);
return res.status(500).json({ error: "Server error" });
}
});

app.get("/health", (_, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`RightGlaze draft order app listening on ${PORT}`));
