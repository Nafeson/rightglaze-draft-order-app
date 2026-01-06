// server.js (ESM)
// RightGlaze Draft Order Checkout — DGU + Skylight
// Changes in this version ONLY:
// 1) Line total removed from ALL summaries (no "Line total" customAttribute anywhere)
// 2) DGU summary "Size" shows Height then Width

import express from "express";
import crypto from "crypto";

const app = express();

/* =========================
ENV
========================= */
function mustEnv(name) {
const v = process.env[name];
if (!v) throw new Error(`Missing required env var: ${name}`);
return v;
}

const SHOPIFY_SHOP_DOMAIN = mustEnv("SHOPIFY_SHOP_DOMAIN"); // e.g. yourshop.myshopify.com
const SHOPIFY_ADMIN_ACCESS_TOKEN = mustEnv("SHOPIFY_ADMIN_ACCESS_TOKEN");
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-10";

const FRONTEND_SHARED_SECRET = mustEnv("FRONTEND_SHARED_SECRET");

// Anchor variants used to force a product image in draft order / invoice
const ANCHOR_VARIANT_GID_DGU = mustEnv("ANCHOR_VARIANT_GID_DGU");
const ANCHOR_VARIANT_GID_SKYLIGHT = mustEnv("ANCHOR_VARIANT_GID_SKYLIGHT");

/* =========================
CORS / PREFLIGHT (no 'cors' package)
========================= */
app.use((req, res, next) => {
res.setHeader("Access-Control-Allow-Origin", "*");
res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS, GET");
res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-RG-Timestamp, X-RG-Signature");
res.setHeader("Access-Control-Max-Age", "86400");
if (req.method === "OPTIONS") return res.status(204).end();
next();
});

app.use(express.json({ limit: "1mb" }));

/* =========================
HELPERS
========================= */
function money2(n) {
const x = Number(n);
if (!Number.isFinite(x)) return "0.00";
return x.toFixed(2);
}

function safeStr(v) {
if (v === null || v === undefined) return "";
return String(v);
}

function hmacSha256Hex(secret, message) {
return crypto.createHmac("sha256", secret).update(message).digest("hex");
}

function timingSafeEqualHex(a, b) {
try {
const ba = Buffer.from(String(a || ""), "hex");
const bb = Buffer.from(String(b || ""), "hex");
if (ba.length !== bb.length) return false;
return crypto.timingSafeEqual(ba, bb);
} catch {
return false;
}
}

function verifySignedBody(req, rawBody) {
const ts = req.get("X-RG-Timestamp") || "";
const sig = req.get("X-RG-Signature") || "";
if (!ts || !sig) return { ok: false, reason: "Missing signature headers" };

const toSign = `${ts}.${rawBody}`;
const expected = hmacSha256Hex(FRONTEND_SHARED_SECRET, toSign);
const ok = timingSafeEqualHex(expected, sig);
return ok ? { ok: true } : { ok: false, reason: "Invalid signature" };
}

async function shopifyGraphql(query, variables) {
const url = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

const res = await fetch(url, {
method: "POST",
headers: {
"Content-Type": "application/json",
"X-Shopify-Access-Token": SHOPIFY_ADMIN_ACCESS_TOKEN,
},
body: JSON.stringify({ query, variables }),
});

const text = await res.text();
let data;
try {
data = JSON.parse(text);
} catch {
throw new Error(`Shopify non-JSON response (${res.status}): ${text.slice(0, 200)}`);
}

if (!res.ok) {
throw new Error(`Shopify HTTP ${res.status}: ${text}`);
}
if (data.errors?.length) {
throw new Error(`Shopify GraphQL errors: ${JSON.stringify(data.errors)}`);
}
return data.data;
}

function buildAnchorLineItem(calculatorType) {
const variantId =
calculatorType === "dgu" ? ANCHOR_VARIANT_GID_DGU : ANCHOR_VARIANT_GID_SKYLIGHT;

return {
variantId,
quantity: 1,
// Make anchor free and harmless
originalUnitPrice: "0.00",
// No customAttributes needed here; image comes from variant
};
}

/* =========================
SUMMARY BUILDERS (customAttributes)
NOTE: line totals removed everywhere.
========================= */

// DGU: show Size as HEIGHT then WIDTH (requested change)
function dguSizeValue(u) {
const h = Number(u.heightMm ?? u.h ?? u.height ?? 0);
const w = Number(u.widthMm ?? u.w ?? u.width ?? 0);
if (Number.isFinite(h) && h > 0 && Number.isFinite(w) && w > 0) {
return `${h}mm × ${w}mm`; // ✅ height then width
}
return "";
}

// Skylight: keep existing summary shape/order (as per your working version),
// just ensure we never add "Line total".
function skylightInternalValue(u) {
const h = Number(u.heightMm ?? u.h ?? 0);
const w = Number(u.widthMm ?? u.w ?? 0);
if (Number.isFinite(h) && h > 0 && Number.isFinite(w) && w > 0) {
return `${h}mm × ${w}mm`; // skylight internal is height then width in your spec
}
return "";
}
function skylightExternalValue(u) {
const h = Number(u.extHeightMm ?? u.extH ?? 0);
const w = Number(u.extWidthMm ?? u.extW ?? 0);
if (Number.isFinite(h) && h > 0 && Number.isFinite(w) && w > 0) {
return `${h}mm × ${w}mm`; // height then width
}
return "";
}

function pushAttr(attrs, name, value) {
const v = safeStr(value).trim();
if (!v) return;
attrs.push({ key: name, value: v });
}

// DGU: include all option inputs (as previously requested in your flow).
// We won’t invent new fields; we’ll include any known/commonly-sent fields if present.
function buildDguAttributes(u) {
const attrs = [];

pushAttr(attrs, "Calculator", "DGU");
pushAttr(attrs, "Size", dguSizeValue(u));

// Common DGU fields (only included if present)
pushAttr(attrs, "Outer Glass", u.outerGlass);
pushAttr(attrs, "Cavity", u.cavity);
pushAttr(attrs, "Inner Glass", u.innerGlass);

pushAttr(attrs, "Spacer Colour", u.spacerColour ?? u.spacerColor);
pushAttr(attrs, "Gas Fill", u.gasFill ?? u.gas);
pushAttr(attrs, "Warm Edge", u.warmEdge);
pushAttr(attrs, "Self Cleaning", u.selfCleaning);
pushAttr(attrs, "Solar Control", u.solarControl);
pushAttr(attrs, "Tint", u.tint);

// If your DGU payload includes any additional option keys, add them here in the same pattern.
// (Leaving structure unchanged beyond the requested Size order.)

return attrs;
}

// Skylight: order you specified earlier:
// Calculator
// Internal
// Unit Strength
// Glazing
// Tint
// Solar Control (omit if "No")
// Self Cleaning (omit if "No")
// External (last)
function buildSkylightAttributes(u) {
const attrs = [];

pushAttr(attrs, "Calculator", "Skylight");
pushAttr(attrs, "Internal", skylightInternalValue(u));
pushAttr(attrs, "Unit Strength", u.unitStrength);
pushAttr(attrs, "Glazing", u.glazing);
pushAttr(attrs, "Tint", u.tint);

// Omit if not selected (expects "Yes"/"No")
if (safeStr(u.solarControl).trim() === "Yes") pushAttr(attrs, "Solar Control", "Yes");
if (safeStr(u.selfCleaning).trim() === "Yes") pushAttr(attrs, "Self Cleaning", "Yes");

// External last (pulls from extWidthMm/extHeightMm in payload)
pushAttr(attrs, "External", skylightExternalValue(u));

return attrs;
}

function calcGrandTotalFromPayload(body) {
// Prefer explicit grandTotal if present and numeric, else compute from units.
const gt = Number(body?.grandTotal);
if (Number.isFinite(gt) && gt >= 0) return gt;

const units = Array.isArray(body?.units) ? body.units : [];
return units.reduce((sum, u) => {
const qty = Number(u?.qty) || 0;
const unitPrice = Number(u?.unitPrice) || 0;
return sum + qty * unitPrice;
}, 0);
}

function buildLineItemsFromPayload(body) {
const calculatorType = safeStr(body?.calculatorType).toLowerCase().trim();
const units = Array.isArray(body?.units) ? body.units : [];

const items = [];
// Anchor line item first (forces image)
items.push(buildAnchorLineItem(calculatorType === "skylight" ? "skylight" : "dgu"));

for (const u of units) {
const qty = Math.max(1, Math.min(100, Number(u?.qty) || 1));
const unitPrice = Number(u?.unitPrice);
const unitPriceStr = Number.isFinite(unitPrice) ? money2(unitPrice) : "0.00";

// Title shown on line item in draft order (keep simple)
const title =
calculatorType === "skylight"
? "Skylight — Custom"
: "DGU — Custom";

const customAttributes =
calculatorType === "skylight" ? buildSkylightAttributes(u) : buildDguAttributes(u);

items.push({
title,
quantity: qty,
// IMPORTANT: per-unit price (Shopify calculates totals with quantity)
originalUnitPrice: unitPriceStr,
customAttributes,
});
}

return { calculatorType, items };
}

/* =========================
ROUTES
========================= */
app.get("/", (req, res) => res.json({ ok: true }));
app.get("/health", (req, res) => res.json({ ok: true }));

app.post("/checkout", async (req, res) => {
// Verify HMAC against raw body
const rawBody = JSON.stringify(req.body ?? {});
const sig = verifySignedBody(req, rawBody);
if (!sig.ok) {
return res.status(401).json({ error: "Unauthorized", reason: sig.reason });
}

try {
const body = req.body || {};
const { calculatorType, items: lineItems } = buildLineItemsFromPayload(body);

const totalUnitsQty = Number(body?.totalUnitsQty) || 0;
const grandTotal = calcGrandTotalFromPayload(body);

const noteLines = [
"Created via RightGlaze calculator checkout",
`Calculator Type: ${calculatorType || "unknown"}`,
`Total Units Qty: ${totalUnitsQty || 0}`,
`Grand Total: £${money2(grandTotal)}`,
];
const note = noteLines.join("\n");

const tags = [`calculator:${calculatorType || "unknown"}`];

const mutation = `
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

const variables = {
input: {
note,
tags,
lineItems,
},
};

const data = await shopifyGraphql(mutation, variables);
const out = data?.draftOrderCreate;

if (out?.userErrors?.length) {
return res.status(400).json({ error: "Shopify userErrors", userErrors: out.userErrors });
}

const invoiceUrl = out?.draftOrder?.invoiceUrl;
if (!invoiceUrl) {
return res.status(500).json({ error: "Checkout created but invoice URL missing." });
}

return res.status(200).json({ invoiceUrl });
} catch (e) {
console.error("Server error", e);
return res.status(500).json({ error: "Server error", reason: e?.message || String(e) });
}
});

/* =========================
START
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
console.log(`RightGlaze draft-order app listening on :${PORT}`);
});
