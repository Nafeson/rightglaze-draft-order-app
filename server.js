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

if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))) {
throw new Error("Invalid signature");
}
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
DISCOUNT FORMATTER (NEW)
========================= */
function formatDiscount(u) {
const pct =
u.discountPercent ??
u.discountPct ??
u.discountRate ??
u.discountPercentInt ??
null;

const saving =
u.discountSaving ??
u.discountSave ??
u.discountAmount ??
u.saving ??
null;

// If calculator sends a ready-made label, prefer it
if (u.discountLabel && String(u.discountLabel).trim()) return String(u.discountLabel).trim();

const pctNum = Number(pct);
const savingNum = Number(saving);

if (Number.isFinite(pctNum) && pctNum > 0 && Number.isFinite(savingNum) && savingNum > 0) {
return `${pctNum}% saving ${fmtGBP(savingNum)}`;
}

// If only percent exists
if (Number.isFinite(pctNum) && pctNum > 0) {
return `${pctNum}% discount`;
}

// If only saving exists
if (Number.isFinite(savingNum) && savingNum > 0) {
return `Saving ${fmtGBP(savingNum)}`;
}

return "";
}

/* =========================
SUMMARY BUILDERS
========================= */
function buildDguAttributes(u) {
const a = [];

// Size first (existing behaviour)
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

// Unit price only if qty > 1 (NO line total)
if (Number(u.qty) > 1) {
a.push({ key: "Unit Price", value: fmtGBP(u.unitPrice) });
}

// Keep Discount attribute if present (NO line total)
const discountText = formatDiscount(u);
if (discountText) a.push({ key: "Discount", value: discountText });

return a;
}

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

// Unit price only if qty > 1 (NO line total)
if (Number(u.qty) > 1) {
a.push({ key: "Unit Price", value: fmtGBP(u.unitPrice) });
}

// Keep Discount attribute if present (NO line total)
const discountText = formatDiscount(u);
if (discountText) a.push({ key: "Discount", value: discountText });

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
// per-unit price (should already be DISCOUNTED by the calculator payload)
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
