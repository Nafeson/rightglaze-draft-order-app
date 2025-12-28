import express from "express";
import crypto from "crypto";

const app = express();

// Capture raw body for signature verification
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
SHOPIFY_API_SECRET, // still used by your other code; fine to keep
SHOPIFY_API_VERSION = "2025-10",
PRESENTMENT_CURRENCY = "GBP",
PORT = 3000,

// ✅ Set in Render
ALLOWED_ORIGIN,
FRONTEND_SHARED_SECRET,
} = process.env;

if (!SHOPIFY_SHOP || !SHOPIFY_ADMIN_TOKEN || !SHOPIFY_API_SECRET) {
console.error(
"Missing env. Need SHOPIFY_SHOP, SHOPIFY_ADMIN_TOKEN, SHOPIFY_API_SECRET."
);
process.exit(1);
}
if (!ALLOWED_ORIGIN || !FRONTEND_SHARED_SECRET) {
console.error("Missing env. Need ALLOWED_ORIGIN, FRONTEND_SHARED_SECRET.");
process.exit(1);
}

/* =========================
CORS (allow only your site)
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
PRICING (INC VAT)
========================= */

const PRICING = {
BASE_RATE: 150,
MIN_PRICE: 72.07,
MM_FACTOR: 0.002,
};

// Returns unit price INC VAT (matches your calculator Stage 1)
function calcUnitPriceIncVat(unit) {
const { outerGlass, innerGlass, selfCleaning, widthMm, heightMm } = unit;
if (
!Number.isFinite(widthMm) ||
!Number.isFinite(heightMm) ||
widthMm <= 0 ||
heightMm <= 0
)
return 0;

// Stage 1 priced config
if (
outerGlass === "4mm Clear" &&
innerGlass === "4mm Clear" &&
selfCleaning === "No"
) {
const areaM2 = (widthMm * heightMm) / 1_000_000;
const areaCost = areaM2 * PRICING.BASE_RATE;
const mmAdj = (widthMm + heightMm) * PRICING.MM_FACTOR;
return Math.max(PRICING.MIN_PRICE, areaCost) + mmAdj; // INC VAT
}

return 0; // unpriced until more stages added
}

/* =========================
RULES (mirror calculator)
========================= */

function clampDims(w, h) {
const min = 150,
maxW = 2000,
maxH = 3000;
const cw = Math.min(maxW, Math.max(min, w));
const ch = Math.min(maxH, Math.max(min, h));
return { w: cw, h: ch };
}

function applyAreaRule(unit) {
const AREA_LIMIT = 2.5;
const areaM2 = (unit.widthMm * unit.heightMm) / 1_000_000;

if (
areaM2 >= AREA_LIMIT &&
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
const w = Number(raw.widthMm);
const h = Number(raw.heightMm);
const { w: cw, h: ch } = clampDims(w, h);

const unit = {
qty: Math.min(10, Math.max(1, Number(raw.qty) || 1)),
outerGlass: String(raw.outerGlass || ""),
innerGlass: String(raw.innerGlass || ""),
cavityWidth: String(raw.cavityWidth || ""),
selfCleaning: String(raw.selfCleaning || "No"),
spacer: String(raw.spacer || ""),
widthMm: cw,
heightMm: ch,
toughened: "Yes",
};

return applyAreaRule(unit);
}

/* =========================
SIGNATURE VERIFICATION (HMAC)
signature = HMAC_SHA256(secret, `${timestamp}.${rawBody}`)
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

if (!ts || !sig) return { ok: false, reason: "Missing signature headers" };

// prevent replay: require timestamp within 5 minutes
const tsNum = Number(ts);
if (!Number.isFinite(tsNum)) return { ok: false, reason: "Invalid timestamp" };
const skewMs = Math.abs(Date.now() - tsNum);
if (skewMs > 5 * 60 * 1000)
return { ok: false, reason: "Timestamp too old/new" };

const raw = req.rawBody ? req.rawBody.toString("utf8") : "";
const payloadToSign = `${ts}.${raw}`;
const digest = crypto
.createHmac("sha256", FRONTEND_SHARED_SECRET)
.update(payloadToSign)
.digest("hex");

if (!timingSafeEqualHex(sig, digest))
return { ok: false, reason: "Bad signature" };
return { ok: true };
}

/* =========================
SHOPIFY GRAPHQL
========================= */

async function shopifyGraphQL(query, variables) {
const url = `https://${SHOPIFY_SHOP}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

const res = await fetch(url, {
method: "POST",
headers: {
"Content-Type": "application/json",
"X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
},
body: JSON.stringify({ query, variables }),
});

const json = await res.json();
if (!res.ok)
throw new Error(`Shopify HTTP ${res.status}: ${JSON.stringify(json)}`);
if (json.errors?.length)
throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
return json.data;
}

// VAT portion when prices are INC VAT @ 20%
// VAT = gross * 20/120 = gross/6
function vatPortionFromGross(gross) {
return gross / 6;
}

function formatBreakdown(units, totals) {
const lines = [];
lines.push("RightGlaze Bespoke Units – Breakdown (prices inc VAT)");
lines.push(`Units: ${units.length}`);
lines.push("");

units.forEach((u, i) => {
const unitPrice = u._unitPriceIncVat;
const lineTotal = unitPrice * u.qty;
const area = (u.widthMm * u.heightMm) / 1_000_000;

lines.push(`Unit ${i + 1} (Qty ${u.qty})`);
lines.push(`- Outer: ${u.outerGlass}`);
lines.push(`- Inner: ${u.innerGlass}`);
lines.push(`- Cavity: ${u.cavityWidth}`);
lines.push(`- Toughened: Yes`);
lines.push(`- Self-cleaning: ${u.selfCleaning}`);
lines.push(`- Spacer: ${u.spacer}`);
lines.push(
`- Size: ${u.widthMm}mm × ${u.heightMm}mm (${area.toFixed(3)} m²)`
);
if (u._areaUpgradeApplied)
lines.push(`- Note: Auto-upgraded due to area ≥ 2.5m²`);
lines.push(`- Unit price: £${unitPrice.toFixed(2)} (inc VAT)`);
if (u.qty >= 2) lines.push(`- Line total: £${lineTotal.toFixed(2)} (inc VAT)`);
lines.push("");
});

lines.push(`ORDER TOTAL: £${totals.gross.toFixed(2)} (inc VAT)`);
lines.push(`VAT (20%): £${totals.vat.toFixed(2)}`);
return lines.join("\n");
}

/* =========================
✅ DIRECT CHECKOUT ENDPOINT
========================= */

app.post("/checkout", async (req, res) => {
try {
const origin = req.headers.origin || "";
if (origin !== ALLOWED_ORIGIN)
return res.status(403).json({ error: "Origin not allowed" });
setCors(res, origin);

const sigOk = verifyFrontendSignature(req);
if (!sigOk.ok)
return res.status(401).json({ error: "Unauthorized", reason: sigOk.reason });

const unitsRaw = req.body?.units;
if (!Array.isArray(unitsRaw) || unitsRaw.length === 0) {
return res.status(400).json({ error: "Missing units[]" });
}

const units = unitsRaw.map(normalizeUnit);

let grossTotal = 0;
for (const u of units) {
const unitPrice = calcUnitPriceIncVat(u);
u._unitPriceIncVat = unitPrice;
grossTotal += unitPrice * u.qty;
}

// Round once at end
grossTotal = Number(grossTotal.toFixed(2));

if (grossTotal <= 0) {
return res.status(422).json({
error:
"This configuration is currently unpriced (total £0.00). Add more pricing stages before enabling checkout.",
});
}

const vat = Number(vatPortionFromGross(grossTotal).toFixed(2));

const totals = {
gross: grossTotal,
vat,
};

const breakdown = formatBreakdown(units, totals);

const mutation = `
mutation draftOrderCreate($input: DraftOrderInput!) {
draftOrderCreate(input: $input) {
draftOrder { id invoiceUrl name }
userErrors { field message }
}
}
`;

// ✅ IMPORTANT: send GROSS total as priceOverride so checkout total always matches
const input = {
note: breakdown,
tags: ["rightglaze", "bespoke", "calculator"],
presentmentCurrencyCode: PRESENTMENT_CURRENCY,
lineItems: [
{
title: "Bespoke Double Glazed Units (Custom Order)",
quantity: 1,
requiresShipping: true,
taxable: true,
priceOverride: {
amount: totals.gross,
currencyCode: PRESENTMENT_CURRENCY,
},
customAttributes: [
{ key: "Units Count", value: String(units.length) },
{ key: "Order Total (inc VAT)", value: `£${totals.gross.toFixed(2)}` },
{ key: "VAT (20%)", value: `£${totals.vat.toFixed(2)}` },
],
},
],
};

const data = await shopifyGraphQL(mutation, { input });
const payload = data?.draftOrderCreate;

if (!payload) throw new Error("No draftOrderCreate payload returned.");

if (payload.userErrors?.length) {
return res.status(400).json({ error: "Draft order error", details: payload.userErrors });
}

const invoiceUrl = payload.draftOrder?.invoiceUrl;
if (!invoiceUrl)
return res.status(500).json({ error: "Draft order created but invoiceUrl missing." });

// ✅ return grossTotal so frontend can show correct number too
return res.json({ invoiceUrl, grandTotal: totals.gross, vatAmount: totals.vat });
} catch (err) {
console.error(err);
return res.status(500).json({ error: "Server error", message: err.message });
}
});

app.get("/health", (req, res) => res.json({ ok: true }));

app.listen(PORT, () =>
console.log(`RightGlaze draft order app listening on port ${PORT}`)
);
