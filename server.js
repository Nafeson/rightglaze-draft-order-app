// server.js (ESM)

// =====================
// ENV VARS (Render)
// =====================
// Required:
// - SHOPIFY_SHOP_DOMAIN                  e.g. "rightglaze.myshopify.com"
// - SHOPIFY_ADMIN_ACCESS_TOKEN           Admin API access token
// - FRONTEND_SHARED_SECRET               same secret as calculators use for HMAC
// - ANCHOR_VARIANT_GID_DGU               e.g. "gid://shopify/ProductVariant/123..."
// - ANCHOR_VARIANT_GID_SKYLIGHT          e.g. "gid://shopify/ProductVariant/456..."
// Optional:
// - ALLOWED_ORIGINS                      comma-separated list, e.g. "https://www.rightglaze.co.uk,https://rightglaze.co.uk"

import express from "express";
import crypto from "crypto";

const app = express();
app.set("trust proxy", 1);

// IMPORTANT for preflight: parse JSON after CORS headers are set
app.use(express.json({ limit: "1mb" }));

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

// =====================
// CORS + PREFLIGHT FIX
// =====================
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

function setCors(req, res) {
  const origin = req.headers.origin;

  // If you haven't set ALLOWED_ORIGINS, reflect origin (works for Shopify storefront pages).
  // If you DID set it, only allow listed origins.
  const allow =
    allowedOrigins.length === 0
      ? origin
      : (origin && allowedOrigins.includes(origin) ? origin : "");

  if (allow) {
    res.setHeader("Access-Control-Allow-Origin", allow);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,X-RG-Timestamp,X-RG-Signature"
  );
  res.setHeader("Access-Control-Max-Age", "86400");
}

// Preflight handler
app.options("/checkout", (req, res) => {
  setCors(req, res);
  return res.status(204).send("");
});

// Also set CORS headers on all responses for this endpoint
app.use((req, res, next) => {
  if (req.path === "/checkout") setCors(req, res);
  next();
});

// =====================
// HMAC VERIFY
// =====================
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

function verifyHmac({ secret, timestamp, rawBody, signatureHex, maxSkewMs = 5 * 60 * 1000 }) {
  if (!timestamp || !signatureHex) return { ok: false, reason: "missing_headers" };

  const tsNum = Number(timestamp);
  if (!Number.isFinite(tsNum)) return { ok: false, reason: "bad_timestamp" };

  const skew = Math.abs(Date.now() - tsNum);
  if (skew > maxSkewMs) return { ok: false, reason: "timestamp_skew" };

  const toSign = `${timestamp}.${rawBody}`;
  const expected = crypto.createHmac("sha256", secret).update(toSign).digest("hex");

  if (!timingSafeEqualHex(expected, signatureHex)) return { ok: false, reason: "bad_signature" };
  return { ok: true };
}

// =====================
// SHOPIFY GRAPHQL
// =====================
const SHOPIFY_GRAPHQL_ENDPOINT = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-01/graphql.json`;

async function shopifyGraphql(query, variables) {
  const res = await fetch(SHOPIFY_GRAPHQL_ENDPOINT, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_ACCESS_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    throw new Error(`Shopify GraphQL non-JSON response (${res.status}): ${text.slice(0, 300)}`);
  }

  if (!res.ok) {
    throw new Error(`Shopify GraphQL HTTP ${res.status}: ${text.slice(0, 600)}`);
  }

  if (json.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
  }

  return json.data;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// Re-query invoiceUrl if Shopify returns it late
async function fetchInvoiceUrlWithRetry(draftOrderGid, attempts = 10, delayMs = 250) {
  const q = `
    query DraftOrderInvoiceUrl($id: ID!) {
      draftOrder(id: $id) {
        id
        invoiceUrl
      }
    }
  `;

  for (let i = 0; i < attempts; i++) {
    const data = await shopifyGraphql(q, { id: draftOrderGid });
    const url = data?.draftOrder?.invoiceUrl || null;
    if (url) return url;
    await sleep(delayMs);
  }
  return null;
}

// =====================
// BUILD LINE ITEMS
// =====================
function pickAnchorVariant(calculatorType) {
  const t = String(calculatorType || "").toLowerCase();
  if (t === "skylight") return ANCHOR_VARIANT_GID_SKYLIGHT;
  return ANCHOR_VARIANT_GID_DGU; // default to dgu
}

// Simple readable titles (capitalised outputs)
function titleForUnit(calculatorType, u) {
  const t = String(calculatorType || "").toLowerCase();

  if (t === "skylight") {
    // Example output: "Skylight — Toughened / Double Glazed — 800mm × 1200mm (Internal) — Qty 2"
    const strength = u.unitStrength ? String(u.unitStrength) : "—";
    const glazing = u.glazing ? String(u.glazing) : "—";
    const w = Number(u.widthMm);
    const h = Number(u.heightMm);
    const qty = Number(u.qty) || 1;
    const dims = (Number.isFinite(w) && Number.isFinite(h)) ? `${w}mm × ${h}mm` : "—";
    return `Skylight — ${strength} / ${glazing} — ${dims} (Internal) — Qty ${qty}`;
  }

  // DGU
  // Example output: "DGU — 4mm Clear / 4mm Softcoat — 600mm × 900mm — Qty 3"
  const outer = u.outerGlass ? String(u.outerGlass) : "—";
  const inner = u.innerGlass ? String(u.innerGlass) : "—";
  const w = Number(u.widthMm);
  const h = Number(u.heightMm);
  const qty = Number(u.qty) || 1;
  const dims = (Number.isFinite(w) && Number.isFinite(h)) ? `${w}mm × ${h}mm` : "—";
  return `DGU — ${outer} / ${inner} — ${dims} — Qty ${qty}`;
}

// We put each unit as a *custom line item* priced at lineTotal (qty already baked in).
// Anchor variant is a normal variant line item at £0 so checkout has product imagery.
function buildDraftOrderLineItems({ calculatorType, units }) {
  const anchorVariantId = pickAnchorVariant(calculatorType);

  const items = [];

  // Anchor product to force image/title in checkout
  items.push({
    variantId: anchorVariantId,
    quantity: 1,
    // keep it free
    originalUnitPrice: "0.00",
  });

  for (const u of units || []) {
    const qty = Math.max(1, Math.min(10, Number(u.qty) || 1));
    const lineTotal = Number(u.lineTotal);
    const priced = Number.isFinite(lineTotal) ? lineTotal : 0;

    // We store the total for that unit line as a single priced item at quantity 1
    // because Shopify custom items use "quantity" too; keeping quantity 1 avoids doubling.
    items.push({
      title: titleForUnit(calculatorType, u),
      quantity: 1,
      originalUnitPrice: priced.toFixed(2),
      // optional: add tax - most stores handle tax automatically; leave blank
      // taxable: true,
    });
  }

  return items;
}

// =====================
// CHECKOUT ENDPOINT
// =====================
app.post("/checkout", async (req, res) => {
  try {
    // HMAC verify with RAW body string (re-serialize req.body deterministically)
    // NOTE: This matches your frontend which signs JSON.stringify(payload)
    const timestamp = req.header("X-RG-Timestamp");
    const signature = req.header("X-RG-Signature");
    const rawBody = JSON.stringify(req.body ?? {});

    const ok = verifyHmac({
      secret: FRONTEND_SHARED_SECRET,
      timestamp,
      rawBody,
      signatureHex: signature,
    });

    if (!ok.ok) {
      return res.status(401).json({ error: "Unauthorized", reason: ok.reason });
    }

    const calculatorType = req.body?.calculatorType || "dgu";
    const units = Array.isArray(req.body?.units) ? req.body.units : [];

    // Grand total from payload (preferred) or recompute from units
    const payloadGrandTotal = Number(req.body?.grandTotal);
    const computedGrandTotal = units.reduce((sum, u) => sum + (Number(u.lineTotal) || 0), 0);
    const grandTotal = Number.isFinite(payloadGrandTotal) ? payloadGrandTotal : computedGrandTotal;

    const totalUnitsQty = Number(req.body?.totalUnitsQty) || units.reduce((s, u) => s + (Number(u.qty) || 0), 0);

    const lineItems = buildDraftOrderLineItems({ calculatorType, units });

    const noteAttributes = [
      { name: "Calculator Type", value: String(calculatorType) },
      { name: "Total Units Qty", value: String(totalUnitsQty) },
      { name: "Grand Total", value: `£${grandTotal.toFixed(2)}` },
    ];

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

    const input = {
      // You can set an email if you want Shopify to email invoices; not required for invoiceUrl
      // email: "customer@example.com",
      note: "Created via RightGlaze calculator checkout",
      noteAttributes,
      tags: [`calculator:${String(calculatorType).toLowerCase()}`],
      lineItems,
      // If you want to force tax behavior, you can add:
      // taxExempt: false,
      // useCustomerDefaultAddress: false,
    };

    const data = await shopifyGraphql(mutation, { input });

    const payload = data?.draftOrderCreate;
    const userErrors = payload?.userErrors || [];
    if (userErrors.length) {
      return res.status(400).json({ error: "Shopify userErrors", userErrors });
    }

    const draftOrder = payload?.draftOrder;
    const draftOrderId = draftOrder?.id;
    let invoiceUrl = draftOrder?.invoiceUrl || null;

    // If Shopify didn’t return invoiceUrl immediately, retry by querying the created draft order
    if (!invoiceUrl && draftOrderId) {
      invoiceUrl = await fetchInvoiceUrlWithRetry(draftOrderId, 10, 250);
    }

    if (!invoiceUrl) {
      return res.status(502).json({
        error: "Checkout created but invoice URL missing",
        reason: "invoiceUrl_null",
        draftOrderId,
      });
    }

    return res.status(200).json({ invoiceUrl, draftOrderId });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Server error",
      message: err?.message || String(err),
    });
  }
});

// health
app.get("/", (_req, res) => res.status(200).send("OK"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
