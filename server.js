// server.js (ESM)

import express from "express";
import crypto from "crypto";

const app = express();
app.set("trust proxy", 1);

// =====================
// ENV VARS (Render)
// =====================
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

// Optional: comma-separated list of allowed origins
const allowedOrigins = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(s => s.trim())
  .filter(Boolean);

// =====================
// CORS + PREFLIGHT
// =====================
function setCors(req, res) {
  const origin = req.headers.origin;

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

app.options("/checkout", (req, res) => {
  setCors(req, res);
  return res.status(204).send("");
});

app.use((req, res, next) => {
  if (req.path === "/checkout") setCors(req, res);
  next();
});

// =====================
// RAW BODY CAPTURE (CRITICAL FOR HMAC)
// =====================
app.post("/checkout", express.raw({ type: "application/json", limit: "1mb" }));

function parseJsonRaw(buf) {
  try {
    const s = Buffer.isBuffer(buf) ? buf.toString("utf8") : String(buf || "");
    return { ok: true, raw: s, json: s ? JSON.parse(s) : {} };
  } catch (e) {
    return { ok: false, error: "bad_json", message: e?.message || String(e) };
  }
}

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
    throw new Error(`Shopify GraphQL non-JSON response (HTTP ${res.status}): ${text.slice(0, 300)}`);
  }

  if (!res.ok) {
    throw new Error(`Shopify GraphQL HTTP ${res.status}: ${text.slice(0, 800)}`);
  }

  if (json.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors).slice(0, 2000)}`);
  }

  return json.data;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

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
// LINE ITEMS (IMPORTANT FIX)
// =====================
// Shopify checkout only shows images for VARIANT line items.
// Custom line items (title/price) will always show a grey placeholder.
// So: create EACH unit as a variant line item (anchor variant), and put
// the unit summary into customAttributes (line item properties).
function pickAnchorVariant(calculatorType) {
  const t = String(calculatorType || "").toLowerCase();
  if (t === "skylight") return ANCHOR_VARIANT_GID_SKYLIGHT;
  return ANCHOR_VARIANT_GID_DGU;
}

function capLabel(s) {
  const x = String(s || "").trim();
  if (!x) return "";
  return x.charAt(0).toUpperCase() + x.slice(1);
}

function formatMoney(n) {
  const v = Number(n);
  return Number.isFinite(v) ? v.toFixed(2) : "0.00";
}

function buildUnitSummaryString(calculatorType, u) {
  const t = String(calculatorType || "").toLowerCase();

  if (t === "skylight") {
    const strength = u.unitStrength ? String(u.unitStrength) : "—";
    const glazing = u.glazing ? String(u.glazing) : "—";
    const w = Number(u.widthMm);
    const h = Number(u.heightMm);
    const extW = Number(u.extWidthMm);
    const extH = Number(u.extHeightMm);

    const internal = (Number.isFinite(w) && Number.isFinite(h)) ? `${w}×${h}mm` : "—";
    const external = (Number.isFinite(extW) && Number.isFinite(extH)) ? `${extW}×${extH}mm` : "—";

    const tint = u.tint ? String(u.tint) : "—";
    const solar = u.solarControl ? String(u.solarControl) : "—";
    const sc = u.selfCleaning ? String(u.selfCleaning) : "—";

    return `${strength} • ${glazing} • Internal ${internal} • External ${external} • Tint ${tint} • Solar Control ${solar} • Self Cleaning ${sc}`;
  }

  // DGU
  const outer = u.outerGlass ? String(u.outerGlass) : "—";
  const inner = u.innerGlass ? String(u.innerGlass) : "—";
  const cavity = u.cavityWidth ? String(u.cavityWidth) : "—";
  const w = Number(u.widthMm);
  const h = Number(u.heightMm);
  const dims = (Number.isFinite(w) && Number.isFinite(h)) ? `${w}×${h}mm` : "—";
  const spacer = u.spacer ? String(u.spacer) : "—";
  const sc = u.selfCleaning ? String(u.selfCleaning) : "—";

  return `Outer ${outer} • Inner ${inner} • Cavity ${cavity} • ${dims} • Spacer ${spacer} • Self Cleaning ${sc}`;
}

function buildDraftOrderLineItems({ calculatorType, units }) {
  const variantId = pickAnchorVariant(calculatorType);

  return (units || []).map((u) => {
    const lineTotal = Number(u.lineTotal) || 0;
    const unitPrice = Number(u.unitPrice) || 0;
    const qty = Number(u.qty) || 1;

    // These become “line item properties” in Shopify.
    // They are shown underneath the item on draft invoice/checkout.
    const customAttributes = [
      { key: "Calculator", value: capLabel(calculatorType) }, // Capitalised
      { key: "Qty", value: String(qty) },
      { key: "Unit Price", value: `£${formatMoney(unitPrice)}` },
      { key: "Line Total", value: `£${formatMoney(lineTotal)}` },
      { key: "Summary", value: buildUnitSummaryString(calculatorType, u) },
    ];

    return {
      variantId,
      quantity: 1,
      originalUnitPrice: formatMoney(lineTotal),
      customAttributes,
    };
  });
}

// =====================
// CHECKOUT ENDPOINT
// =====================
app.post("/checkout", async (req, res) => {
  const reqId = crypto.randomUUID();

  try {
    const parsed = parseJsonRaw(req.body);
    if (!parsed.ok) {
      console.error(`[${reqId}] Bad JSON body`, parsed.message);
      return res.status(400).json({ error: "Bad JSON", reason: parsed.error, reqId });
    }

    const rawBody = parsed.raw;
    const body = parsed.json;

    const timestamp = req.header("X-RG-Timestamp");
    const signature = req.header("X-RG-Signature");

    const ok = verifyHmac({
      secret: FRONTEND_SHARED_SECRET,
      timestamp,
      rawBody,
      signatureHex: signature,
    });

    if (!ok.ok) {
      console.warn(`[${reqId}] Unauthorized`, ok.reason);
      return res.status(401).json({ error: "Unauthorized", reason: ok.reason, reqId });
    }

    const calculatorType = body?.calculatorType || "dgu";
    const units = Array.isArray(body?.units) ? body.units : [];

    if (!units.length) {
      return res.status(400).json({ error: "No units provided", reason: "units_empty", reqId });
    }

    const payloadGrandTotal = Number(body?.grandTotal);
    const computedGrandTotal = units.reduce((sum, u) => sum + (Number(u.lineTotal) || 0), 0);
    const grandTotal = Number.isFinite(payloadGrandTotal) ? payloadGrandTotal : computedGrandTotal;

    const totalUnitsQty =
      Number(body?.totalUnitsQty) ||
      units.reduce((s, u) => s + (Number(u.qty) || 0), 0);

    const lineItems = buildDraftOrderLineItems({ calculatorType, units });

    // Persist calculator metadata in Draft Order NOTE (safe across API versions)
    const noteLines = [
      "Created via RightGlaze calculator checkout",
      `Calculator Type: ${String(calculatorType)}`,
      `Total Units Qty: ${String(totalUnitsQty)}`,
      `Grand Total: £${grandTotal.toFixed(2)}`,
    ];
    const note = noteLines.join("\n");

    const mutation = `
      mutation DraftOrderCreate($input: DraftOrderInput!) {
        draftOrderCreate(input: $input) {
          draftOrder { id invoiceUrl }
          userErrors { field message }
        }
      }
    `;

    const input = {
      note,
      tags: [
        `calculator:${String(calculatorType).toLowerCase()}`,
        `units:${String(totalUnitsQty)}`,
      ],
      lineItems,
    };

    const data = await shopifyGraphql(mutation, { input });

    const payload = data?.draftOrderCreate;
    const userErrors = payload?.userErrors || [];
    if (userErrors.length) {
      console.error(`[${reqId}] Shopify userErrors`, userErrors);
      return res.status(400).json({ error: "Shopify userErrors", userErrors, reqId });
    }

    const draftOrder = payload?.draftOrder;
    const draftOrderId = draftOrder?.id;
    let invoiceUrl = draftOrder?.invoiceUrl || null;

    if (!invoiceUrl && draftOrderId) {
      invoiceUrl = await fetchInvoiceUrlWithRetry(draftOrderId, 10, 250);
    }

    if (!invoiceUrl) {
      console.error(`[${reqId}] invoiceUrl missing`, { draftOrderId });
      return res.status(502).json({
        error: "Checkout created but invoice URL missing",
        reason: "invoiceUrl_null",
        draftOrderId,
        reqId,
      });
    }

    return res.status(200).json({ invoiceUrl, draftOrderId, reqId });
  } catch (err) {
    console.error(`[${reqId}] Server error`, err);
    return res.status(500).json({
      error: "Server error",
      message: err?.message || String(err),
      reqId,
    });
  }
});

// Health
app.get("/", (_req, res) => res.status(200).send("OK"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server listening on ${PORT}`));
