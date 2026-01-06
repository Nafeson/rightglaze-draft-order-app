/**
* RightGlaze Draft Order App (server.js)
* - Receives calculator payloads (dgu / skylight)
* - Verifies HMAC (timestamp.body)
* - Creates Shopify Draft Order with:
* ✅ correct anchor variant per calculatorType (so image/title show)
* ✅ customAttributes + note storing calculator grandTotal
* ✅ line items for each confirmed unit (priced)
*
* IMPORTANT ENV VARS (Render → Environment):
* - SHOPIFY_ADMIN_ACCESS_TOKEN (required) // Admin API access token
* - SHOPIFY_SHOP_DOMAIN (required) // e.g. rightglaze.myshopify.com
* (Alias supported: SHOPIFY_SHOP)
* - FRONTEND_SHARED_SECRET (required) // must match calculators
* - ANCHOR_VARIANT_GID_DGU (required) // gid://shopify/ProductVariant/...
* - ANCHOR_VARIANT_GID_SKYLIGHT (required) // gid://shopify/ProductVariant/...
* - SHOPIFY_API_VERSION (optional) // default 2024-07
*
* OPTIONAL:
* - ALLOWED_ORIGINS (comma separated) for CORS
*/

import express from "express";
import crypto from "crypto";

const app = express();

/* ---------- Helpers ---------- */
function mustEnv(name, { allowEmpty = false } = {}) {
const v = process.env[name];
if (v === undefined || (!allowEmpty && String(v).trim() === "")) {
throw new Error(`Missing required env var: ${name}`);
}
return v;
}

function getEnv(name, fallback = "") {
const v = process.env[name];
return (v === undefined || String(v).trim() === "") ? fallback : v;
}

function asNumber(x, fallback = 0) {
const n = Number(x);
return Number.isFinite(n) ? n : fallback;
}

function moneyGBP(n) {
const v = asNumber(n, 0);
return `£${v.toFixed(2)}`;
}

function safeStr(x) {
if (x === null || x === undefined) return "";
return String(x);
}

function normalizeCalculatorType(x) {
const t = String(x || "").toLowerCase().trim();
if (t === "skylight") return "skylight";
return "dgu"; // default
}

function calcGrandTotalFromUnits(units) {
if (!Array.isArray(units)) return 0;
return units.reduce((sum, u) => sum + asNumber(u?.lineTotal, 0), 0);
}

/* ---------- ENV (with backwards-compatible alias) ---------- */
const SHOP_DOMAIN = getEnv("SHOPIFY_SHOP_DOMAIN", getEnv("SHOPIFY_SHOP", ""));
if (!SHOP_DOMAIN) {
// keep the same error you were seeing, but allow the alias
throw new Error("Missing required env var: SHOPIFY_SHOP_DOMAIN");
}
const ADMIN_TOKEN = mustEnv("SHOPIFY_ADMIN_ACCESS_TOKEN");
const FRONTEND_SHARED_SECRET = mustEnv("FRONTEND_SHARED_SECRET");

const ANCHOR_VARIANT_GID_DGU = mustEnv("ANCHOR_VARIANT_GID_DGU");
const ANCHOR_VARIANT_GID_SKYLIGHT = mustEnv("ANCHOR_VARIANT_GID_SKYLIGHT");

const API_VERSION = getEnv("SHOPIFY_API_VERSION", "2024-07");

/* ---------- Middleware ---------- */
app.use(express.json({ limit: "1mb" }));

// Basic CORS (optional hardening)
const allowedOrigins = getEnv("ALLOWED_ORIGINS", "")
.split(",")
.map(s => s.trim())
.filter(Boolean);

app.use((req, res, next) => {
const origin = req.headers.origin;
if (!origin) return next();

if (allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
res.setHeader("Access-Control-Allow-Origin", origin);
res.setHeader("Vary", "Origin");
res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-RG-Timestamp, X-RG-Signature");
res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
}

if (req.method === "OPTIONS") return res.sendStatus(204);
next();
});

/* ---------- HMAC verification ---------- */
function hmacSha256Hex(secret, message) {
return crypto.createHmac("sha256", secret).update(message).digest("hex");
}

function timingSafeEqualHex(a, b) {
try {
const ab = Buffer.from(String(a || ""), "hex");
const bb = Buffer.from(String(b || ""), "hex");
if (ab.length !== bb.length) return false;
return crypto.timingSafeEqual(ab, bb);
} catch {
return false;
}
}

function verifySignedRequest(req) {
const ts = req.header("X-RG-Timestamp");
const sig = req.header("X-RG-Signature");
if (!ts || !sig) return { ok: false, reason: "Missing signature headers" };

// Optional replay window (10 minutes)
const now = Date.now();
const tsNum = Number(ts);
if (!Number.isFinite(tsNum)) return { ok: false, reason: "Invalid timestamp" };
if (Math.abs(now - tsNum) > 10 * 60 * 1000) return { ok: false, reason: "Timestamp outside window" };

const rawBody = JSON.stringify(req.body ?? {});
const toSign = `${ts}.${rawBody}`;
const expected = hmacSha256Hex(FRONTEND_SHARED_SECRET, toSign);
const ok = timingSafeEqualHex(expected, sig);
return ok ? { ok: true } : { ok: false, reason: "Bad signature" };
}

/* ---------- Shopify GraphQL ---------- */
async function shopifyGraphQL(query, variables) {
const url = `https://${SHOP_DOMAIN}/admin/api/${API_VERSION}/graphql.json`;

const res = await fetch(url, {
method: "POST",
headers: {
"Content-Type": "application/json",
"X-Shopify-Access-Token": ADMIN_TOKEN
},
body: JSON.stringify({ query, variables })
});

const text = await res.text();
let json;
try { json = JSON.parse(text); } catch { json = { raw: text }; }

if (!res.ok) {
const msg = `Shopify GraphQL HTTP ${res.status}: ${text}`;
const err = new Error(msg);
err.status = res.status;
err.payload = json;
throw err;
}

if (json?.errors?.length) {
const err = new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
err.payload = json;
throw err;
}

return json.data;
}

/* ---------- Draft Order creation ---------- */
function getAnchorVariantGid(calculatorType) {
return calculatorType === "skylight"
? ANCHOR_VARIANT_GID_SKYLIGHT
: ANCHOR_VARIANT_GID_DGU;
}

function labelForCalculatorType(calculatorType) {
// ✅ ensure capitalised output (you asked for this)
return calculatorType === "skylight" ? "Skylight" : "DGU";
}

function buildCalculatorSummaryLines(calculatorType, units) {
// Keep this short but useful; shows on invoice / draft order details.
const lines = [];
lines.push(`${labelForCalculatorType(calculatorType)} Calculator`);

const qtySum = Array.isArray(units)
? units.reduce((s, u) => s + asNumber(u?.qty, 0), 0)
: 0;

if (qtySum) lines.push(`Total Units: ${qtySum}`);
return lines;
}

// Build a readable description per unit for the draft order "custom" line item
function buildUnitTitle(calculatorType, u) {
if (calculatorType === "skylight") {
// Use the same field names your skylight payload sends
const strength = safeStr(u.unitStrength);
const glazing = safeStr(u.glazing);
const tint = safeStr(u.tint);
const sc = safeStr(u.solarControl);
const self = safeStr(u.selfCleaning);

const w = asNumber(u.widthMm, 0);
const h = asNumber(u.heightMm, 0);
const extW = asNumber(u.extWidthMm, 0);
const extH = asNumber(u.extHeightMm, 0);

const bits = [
"Bespoke Frameless Skylight",
strength && `• ${strength}`,
glazing && `• ${glazing}`,
`• Internal ${h}×${w}mm`,
(extH && extW) ? `• External ${extH}×${extW}mm` : "",
tint ? `• Tint ${tint}` : "",
sc ? `• Solar Control ${sc}` : "",
self ? `• Self Cleaning ${self}` : ""
].filter(Boolean);

return bits.join(" ");
}

// DGU
const outer = safeStr(u.outerGlass);
const inner = safeStr(u.innerGlass);
const cavity = safeStr(u.cavityWidth);
const spacer = safeStr(u.spacer);
const self = safeStr(u.selfCleaning);

const w = asNumber(u.widthMm, 0);
const h = asNumber(u.heightMm, 0);

const bits = [
"Bespoke Double Glazed Unit",
outer ? `• Outer ${outer}` : "",
inner ? `• Inner ${inner}` : "",
cavity ? `• Cavity ${cavity}` : "",
`• ${h}×${w}mm`,
spacer ? `• Spacer ${spacer}` : "",
self ? `• Self Cleaning ${self}` : ""
].filter(Boolean);

return bits.join(" ");
}

function buildCustomLineItems(calculatorType, units) {
const items = [];
if (!Array.isArray(units)) return items;

units.forEach((u) => {
const qty = Math.max(1, Math.min(100, asNumber(u?.qty, 1)));
const unitPrice = asNumber(u?.unitPrice, 0);
const lineTotal = asNumber(u?.lineTotal, unitPrice * qty);

// Skip free/invalid items (you already guard this client-side, but keep safe)
if (!(lineTotal > 0) || !(unitPrice > 0)) return;

items.push({
title: buildUnitTitle(calculatorType, u),
quantity: qty,
// DraftOrderCreate input uses originalUnitPrice / originalUnitPriceWithCurrency?
// The safe & supported field is "originalUnitPrice" (Money).
originalUnitPrice: unitPrice.toFixed(2),
// Put extra info into "customAttributes" so the merchant can see it
customAttributes: [
{ key: "Calculator", value: labelForCalculatorType(calculatorType) },
{ key: "Unit Price", value: moneyGBP(unitPrice) },
{ key: "Line Total", value: moneyGBP(lineTotal) }
]
});
});

return items;
}

const DRAFT_ORDER_CREATE = `
mutation DraftOrderCreate($input: DraftOrderInput!) {
draftOrderCreate(input: $input) {
draftOrder {
id
invoiceUrl
}
userErrors {
field
message
}
}
}
`;

/* ---------- Routes ---------- */
app.get("/", (req, res) => {
res.status(200).send("OK");
});

app.post("/checkout", async (req, res) => {
// 1) Verify signature
const sig = verifySignedRequest(req);
if (!sig.ok) {
return res.status(401).json({ error: "Unauthorized", reason: sig.reason });
}

try {
const body = req.body || {};
const calculatorType = normalizeCalculatorType(body.calculatorType);
const units = Array.isArray(body.units) ? body.units : [];

// ✅ grandTotal: prefer client, fallback to sum(lineTotal)
const computedGrandTotal = calcGrandTotalFromUnits(units);
const grandTotal = asNumber(body.grandTotal, computedGrandTotal);

const totalUnitsQty = asNumber(body.totalUnitsQty, units.reduce((s, u) => s + asNumber(u?.qty, 0), 0));

// 2) Anchor line item (variant) to force product image/title in checkout
const anchorVariantId = getAnchorVariantGid(calculatorType);

// 3) Custom line items for each unit
const customLineItems = buildCustomLineItems(calculatorType, units);

// If nothing priced, fail fast
if (customLineItems.length === 0) {
return res.status(400).json({ error: "No priced units to checkout" });
}

// 4) Persist calculator meta to draft order
const summaryLines = buildCalculatorSummaryLines(calculatorType, units);

// ✅ capitalised outputs
const attributes = [
{ key: "Calculator Type", value: labelForCalculatorType(calculatorType) },
{ key: "Grand Total", value: moneyGBP(grandTotal) }, // ✅ THIS IS THE CHANGE YOU ASKED FOR
{ key: "Total Units", value: String(totalUnitsQty) }
];

// 5) Draft order input
const input = {
// NOTE: Keep the draft order open for invoice/checkout
// status: "OPEN", // Shopify sets status; not always accepted here
note: `${summaryLines.join(" • ")} • Grand Total: ${moneyGBP(grandTotal)}`, // ✅ shows in admin; often on invoice
customAttributes: attributes,

// Line items: anchor variant first, then custom items
lineItems: [
{
variantId: anchorVariantId,
quantity: 1
// Price will come from variant; your server can override via appliedDiscount if needed
},
...customLineItems
]
};

const data = await shopifyGraphQL(DRAFT_ORDER_CREATE, { input });
const result = data?.draftOrderCreate;

const userErrors = result?.userErrors || [];
if (userErrors.length) {
return res.status(400).json({
error: "Shopify error",
reason: userErrors.map(e => e.message).join(" | "),
userErrors
});
}

const invoiceUrl = result?.draftOrder?.invoiceUrl;
if (!invoiceUrl) {
return res.status(500).json({ error: "Checkout created but invoiceUrl missing" });
}

return res.status(200).json({ invoiceUrl });
} catch (err) {
console.error(err);

// Make Shopify auth issues obvious
const msg = String(err?.message || "Server error");
if (msg.includes("Invalid API key") || msg.includes("access token") || msg.includes("401")) {
return res.status(500).json({
error: "Shopify auth error",
reason: msg
});
}

return res.status(500).json({ error: "Server error", reason: msg });
}
});

/* ---------- Start ---------- */
const PORT = asNumber(process.env.PORT, 3000);
app.listen(PORT, () => {
console.log(`Server listening on port ${PORT}`);
console.log(`Shop domain: ${SHOP_DOMAIN}`);
});
