// server.js (ESM)
// RightGlaze Draft Order app — DGU + Skylight
// NO external cors dependency

import express from "express";
import crypto from "crypto";

/* =========================
APP
========================= */
const app = express();

/* =========================
ENV
========================= */
function mustEnv(name) {
const v = process.env[name];
if (!v || !String(v).trim()) throw new Error(`Missing required env var: ${name}`);
return String(v).trim();
}

const SHOPIFY_SHOP_DOMAIN = mustEnv("SHOPIFY_SHOP_DOMAIN");
const SHOPIFY_ADMIN_ACCESS_TOKEN = mustEnv("SHOPIFY_ADMIN_ACCESS_TOKEN");
const FRONTEND_SHARED_SECRET = mustEnv("FRONTEND_SHARED_SECRET");

const ANCHOR_VARIANT_GID_DGU = mustEnv("ANCHOR_VARIANT_GID_DGU");
const ANCHOR_VARIANT_GID_SKYLIGHT = mustEnv("ANCHOR_VARIANT_GID_SKYLIGHT");

const PRESENTMENT_CURRENCY_CODE = (process.env.PRESENTMENT_CURRENCY_CODE || "GBP").trim();

/* =========================
RAW BODY (HMAC)
========================= */
app.use(
express.json({
limit: "1mb",
verify: (req, res, buf) => {
req.rawBody = buf.toString("utf8");
},
})
);

/* =========================
CORS (MANUAL)
========================= */
app.use((req, res, next) => {
const origin = req.headers.origin || "*";
res.setHeader("Access-Control-Allow-Origin", origin);
res.setHeader("Vary", "Origin");
res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
res.setHeader(
"Access-Control-Allow-Headers",
"Content-Type, X-RG-Timestamp, X-RG-Signature"
);

if (req.method === "OPTIONS") return res.status(204).end();
next();
});

/* =========================
SECURITY
========================= */
function hmacSha256Hex(secret, msg) {
return crypto.createHmac("sha256", secret).update(msg).digest("hex");
}

function requireValidSignature(req) {
const ts = req.header("X-RG-Timestamp");
const sig = req.header("X-RG-Signature");
if (!ts || !sig) throw new Error("Missing signature headers");

const expected = hmacSha256Hex(FRONTEND_SHARED_SECRET, `${ts}.${req.rawBody}`);

// timingSafeEqual requires same length buffers
const a = Buffer.from(expected, "utf8");
const b = Buffer.from(String(sig), "utf8");
if (a.length !== b.length) throw new Error("Invalid signature");
if (!crypto.timingSafeEqual(a, b)) throw new Error("Invalid signature");
}

/* =========================
HELPERS
========================= */
const money = (n) => ({
amount: Number(n || 0).toFixed(2),
currencyCode: PRESENTMENT_CURRENCY_CODE,
});

const fmtGBP = (n) => `£${Number(n || 0).toFixed(2)}`;

// DGU wants W×H (unchanged)
function dimsWH(w, h) {
const ww = Number(w);
const hh = Number(h);
if (Number.isFinite(ww) && Number.isFinite(hh)) return `${ww}mm × ${hh}mm`;
return "—";
}

// Skylight wants H×W
function dimsHW(h, w) {
const hh = Number(h);
const ww = Number(w);
if (Number.isFinite(hh) && Number.isFinite(ww)) return `${hh}mm × ${ww}mm`;
return "—";
}

const grandTotalFromUnits = (units) =>
units.reduce((sum, u) => sum + (Number(u.lineTotal) || 0), 0);

function pushAttr(arr, key, value) {
if (value === undefined || value === null) return;
const v = String(value).trim();
if (!v) return;
arr.push({ key, value: v });
}

/* =========================
SUMMARY BUILDERS
========================= */
function buildDguAttributes(u) {
const a = [];

// Size first (existing behaviour) — DGU stays W×H
const w = u.widthMm ?? u.w;
const h = u.heightMm ?? u.h;
a.push({ key: "Size", value: dimsWH(w, h) });

// Show all option inputs from DGU calculator
pushAttr(a, "Calculator", "DGU");
pushAttr(a, "Outer Glass", u.outerGlass);
pushAttr(a, "Inner Glass", u.innerGlass);
pushAttr(a, "Cavity Width", u.cavityWidth);

// Toughened is always Yes for DGU calculator
pushAttr(a, "Toughened", u.toughened ?? "Yes");

pushAttr(a, "Self-cleaning", u.selfCleaning);
pushAttr(a, "Spacer", u.spacer);

// Optional: include thickness if payload includes it
pushAttr(a, "Thickness", u.thickness);

// Unit price + line total only if qty > 1 (unchanged)
if (Number(u.qty) > 1) {
a.push({ key: "Unit Price", value: fmtGBP(u.unitPrice) });
a.push({ key: "Line Total", value: fmtGBP(u.lineTotal) });
}

return a;
}

/**
* ✅ UPDATED for Skylight discount changes:
* - Uses discounted unitPrice/lineTotal for pricing (Shopify priceOverride already does)
* - Adds discount info + shows "Was £X.XX → Now £Y.YY" for Unit Price and Line Total when qty > 1
* - Pulls baseUnitPrice/baseLineTotal/discountPct/discountSaving from the skylight calculator payload
*/
function buildSkylightAttributes(u) {
const a = [];

// Pull internal dims from payload (internal is widthMm/heightMm) but DISPLAY as H×W
const internalW = u.widthMm ?? u.w;
const internalH = u.heightMm ?? u.h;

// Pull external dims from payload (must match red popup) but DISPLAY as H×W
const externalW = u.extWidthMm ?? u.extW;
const externalH = u.extHeightMm ?? u.extH;

a.push({ key: "Calculator", value: "Skylight" });

// Internal: height first then width
a.push({ key: "Internal", value: dimsHW(internalH, internalW) });

pushAttr(a, "Unit Strength", u.unitStrength);
pushAttr(a, "Glazing", u.glazing);
pushAttr(a, "Tint", u.tint);

if (String(u.solarControl).toLowerCase() === "yes") {
a.push({ key: "Solar Control", value: "Yes" });
}

if (String(u.selfCleaning).toLowerCase() === "yes") {
a.push({ key: "Self Cleaning", value: "Yes" });
}

// ✅ Discount display (only when discountPct > 0)
const qty = Number(u.qty) || 1;
const discountPct = Number(u.discountPct) || 0;
const discountSaving = Number(u.discountSaving) || 0;

if (discountPct > 0 && discountSaving > 0) {
const pctTxt = `${Math.round(discountPct * 100)}%`;
a.push({ key: "Discount", value: `${pctTxt} (saving ${fmtGBP(discountSaving)})` });
}

// ✅ Show Unit Price + Line Total only if qty > 1
// ✅ Show base (pre-discount) and discounted values
if (qty > 1) {
const baseUnit = Number(u.baseUnitPrice) || 0;
const baseLine = Number(u.baseLineTotal) || 0;
const discUnit = Number(u.unitPrice) || 0;
const discLine = Number(u.lineTotal) || 0;

// Checkout properties are plain text (no real strikethrough), so we show "Was → Now"
a.push({
key: "Unit Price",
value: discountPct > 0 && baseUnit > 0
? `Was ${fmtGBP(baseUnit)} → Now ${fmtGBP(discUnit)}`
: fmtGBP(discUnit),
});

a.push({
key: "Line Total",
value: discountPct > 0 && baseLine > 0
? `Was ${fmtGBP(baseLine)} → Now ${fmtGBP(discLine)}`
: fmtGBP(discLine),
});
}

// External LAST: height first then width
if (Number.isFinite(Number(externalW)) && Number.isFinite(Number(externalH))) {
a.push({ key: "External", value: dimsHW(externalH, externalW) });
}

return a;
}

/* =========================
SHOPIFY GRAPHQL
========================= */
async function shopifyGraphql(query, variables) {
const res = await fetch(
`https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-10/graphql.json`,
{
method: "POST",
headers: {
"Content-Type": "application/json",
"X-Shopify-Access-Token": SHOPIFY_ADMIN_ACCESS_TOKEN,
},
body: JSON.stringify({ query, variables }),
}
);

const json = await res.json();
if (!res.ok || json.errors) {
throw new Error(JSON.stringify(json.errors || json));
}
return json.data;
}

/* =========================
CHECKOUT
========================= */
app.post("/checkout", async (req, res) => {
try {
requireValidSignature(req);

const { calculatorType, units, totalUnitsQty } = req.body;
if (!units || !Array.isArray(units) || units.length === 0) {
throw new Error("No units provided");
}

const isSkylight = calculatorType === "skylight";
const variantId = isSkylight ? ANCHOR_VARIANT_GID_SKYLIGHT : ANCHOR_VARIANT_GID_DGU;

const lineItems = units.map((u) => ({
variantId,
quantity: Number(u.qty) || 1,
// per-unit price (must be DISCOUNTED per-unit price for skylight)
priceOverride: money(u.unitPrice),
customAttributes: isSkylight ? buildSkylightAttributes(u) : buildDguAttributes(u),
}));

const grandTotal = grandTotalFromUnits(units);

const input = {
note: "Created via RightGlaze calculator checkout",
tags: [`calculator:${calculatorType}`],
presentmentCurrencyCode: PRESENTMENT_CURRENCY_CODE,
customAttributes: [
{ key: "Calculator Type", value: String(calculatorType || "").trim() },
{ key: "Total Units Qty", value: String(totalUnitsQty ?? "") },
{ key: "Grand Total", value: fmtGBP(grandTotal) },
],
lineItems,
};

const data = await shopifyGraphql(
`mutation($input: DraftOrderInput!) {
draftOrderCreate(input: $input) {
draftOrder { invoiceUrl }
userErrors { message }
}
}`,
{ input }
);

const out = data?.draftOrderCreate;
if (!out) throw new Error("Unexpected Shopify response");
if (out.userErrors?.length) throw new Error(out.userErrors[0].message);

const invoiceUrl = out.draftOrder?.invoiceUrl;
if (!invoiceUrl) throw new Error("Checkout created but invoice URL missing.");

res.json({ invoiceUrl });
} catch (err) {
console.error(err);
res.status(500).json({
error: "Server error",
reason: String(err?.message || err),
});
}
});

/* =========================
START
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
console.log(`RightGlaze Draft Order app running on ${PORT}`);
});
