/**
 * server.js — RightGlaze Draft Order Checkout Server (DGU + Skylight)
 *
 * Fixes / ensures:
 * ✅ Grand totals “pull through” to checkout/invoice (saved to Draft Order note + note attributes)
 * ✅ Correct product picture at checkout (uses the correct ANCHOR variant per calculator)
 * ✅ Capitalised outputs/labels on line item properties
 *
 * EXPECTED REQUEST (from both calculators):
 *  Headers:
 *   - X-RG-Timestamp: <ms epoch as string>
 *   - X-RG-Signature: <hex hmac sha256 of `${ts}.${rawBody}`>
 *  Body:
 *   {
 *     calculatorType: "dgu" | "skylight",
 *     totalUnitsQty: number,
 *     units: [...]
 *   }
 *
 * ENV VARS REQUIRED:
 *  - SHOPIFY_SHOP_DOMAIN                 e.g. "rightglaze.myshopify.com"
 *  - SHOPIFY_ADMIN_ACCESS_TOKEN          Admin API token
 *  - FRONTEND_SHARED_SECRET              Must match BOTH calculator scripts
 *
 *  - DGU_ANCHOR_VARIANT_GID              "gid://shopify/ProductVariant/..."
 *  - SKYLIGHT_ANCHOR_VARIANT_GID         "gid://shopify/ProductVariant/..."
 *
 * OPTIONAL:
 *  - SHOPIFY_API_VERSION                 defaults "2024-10"
 *  - SIGNATURE_MAX_AGE_MS                defaults 5 minutes
 *  - DGU_ANCHOR_TITLE_OVERRIDE
 *  - SKYLIGHT_ANCHOR_TITLE_OVERRIDE
 */

import express from "express";
import crypto from "crypto";

const app = express();

/* ========= CONFIG ========= */
const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_ADMIN_ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-10";

const FRONTEND_SHARED_SECRET = process.env.FRONTEND_SHARED_SECRET;

const DGU_ANCHOR_VARIANT_GID = process.env.DGU_ANCHOR_VARIANT_GID;
const SKYLIGHT_ANCHOR_VARIANT_GID = process.env.SKYLIGHT_ANCHOR_VARIANT_GID;

const DGU_ANCHOR_TITLE_OVERRIDE = process.env.DGU_ANCHOR_TITLE_OVERRIDE || "";
const SKYLIGHT_ANCHOR_TITLE_OVERRIDE = process.env.SKYLIGHT_ANCHOR_TITLE_OVERRIDE || "";

const SIGNATURE_MAX_AGE_MS = Number(process.env.SIGNATURE_MAX_AGE_MS || 5 * 60 * 1000);

/* ========= BASIC VALIDATION ========= */
function mustEnv(name, value) {
  if (!value) throw new Error(`Missing required env var: ${name}`);
}
mustEnv("SHOPIFY_SHOP_DOMAIN", SHOPIFY_SHOP_DOMAIN);
mustEnv("SHOPIFY_ADMIN_ACCESS_TOKEN", SHOPIFY_ADMIN_ACCESS_TOKEN);
mustEnv("FRONTEND_SHARED_SECRET", FRONTEND_SHARED_SECRET);
mustEnv("DGU_ANCHOR_VARIANT_GID", DGU_ANCHOR_VARIANT_GID);
mustEnv("SKYLIGHT_ANCHOR_VARIANT_GID", SKYLIGHT_ANCHOR_VARIANT_GID);

/* ========= RAW BODY CAPTURE for HMAC ========= */
app.use(
  express.json({
    limit: "2mb",
    verify: (req, res, buf) => {
      req.rawBody = buf?.toString("utf8") || "";
    },
  })
);

/* ========= CORS (adjust if you want stricter) ========= */
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,X-RG-Timestamp,X-RG-Signature");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.status(204).send("");
  next();
});

/* ========= HELPERS ========= */
function hmacSha256Hex(secret, message) {
  return crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

function safeNum(n, fallback = 0) {
  const x = Number(n);
  return Number.isFinite(x) ? x : fallback;
}

function money2(n) {
  // Shopify GraphQL expects strings for money inputs
  return (Math.round(safeNum(n) * 100) / 100).toFixed(2);
}

function titleCaseKey(s) {
  // Turn "selfCleaning" -> "Self Cleaning", "outerGlass" -> "Outer Glass"
  const str = String(s || "");
  if (!str) return "";
  const spaced = str
    .replace(/_/g, " ")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .trim();
  return spaced.replace(/\w\S*/g, (w) => w.charAt(0).toUpperCase() + w.slice(1));
}

function capSentence(s) {
  const str = String(s || "").trim();
  if (!str) return "";
  return str.charAt(0).toUpperCase() + str.slice(1);
}

async function shopifyGraphQL(query, variables) {
  const url = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

  const r = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_ACCESS_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });

  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    throw new Error(`Shopify API error: HTTP ${r.status} ${JSON.stringify(data)}`);
  }

  if (data.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(data.errors)}`);
  }

  return data.data;
}

/* ========= BUILD LINE ITEMS ========= */
function pickAnchor(calculatorType) {
  const type = String(calculatorType || "").toLowerCase();
  if (type === "skylight") {
    return {
      variantId: SKYLIGHT_ANCHOR_VARIANT_GID,
      titleOverride: SKYLIGHT_ANCHOR_TITLE_OVERRIDE,
      label: "Skylight Calculator",
    };
  }
  // default to DGU
  return {
    variantId: DGU_ANCHOR_VARIANT_GID,
    titleOverride: DGU_ANCHOR_TITLE_OVERRIDE,
    label: "Glazed Unit Calculator",
  };
}

function buildDguUnitCustomAttributes(u) {
  // NOTE: keys appear in checkout/invoice, so keep them capitalised.
  const attrs = [];

  const push = (k, v) => {
    const val = String(v ?? "").trim();
    if (val) attrs.push({ key: titleCaseKey(k), value: val });
  };

  push("Outer Glass", u.outerGlass);
  push("Inner Glass", u.innerGlass);
  push("Cavity Width", u.cavityWidth);
  push("Self Cleaning", u.selfCleaning);
  push("Spacer", u.spacer);
  push("Width (mm)", u.widthMm);
  push("Height (mm)", u.heightMm);

  // prices (always 2dp)
  if (safeNum(u.unitPrice) > 0) push("Unit Price", `£${money2(u.unitPrice)}`);
  if (safeNum(u.lineTotal) > 0) push("Line Total", `£${money2(u.lineTotal)}`);

  return attrs;
}

function buildSkylightUnitCustomAttributes(u) {
  const attrs = [];

  const push = (k, v) => {
    const val = String(v ?? "").trim();
    if (val) attrs.push({ key: titleCaseKey(k), value: val });
  };

  push("Unit Strength", u.unitStrength);
  push("Glazing", u.glazing);
  push("Border (mm)", u.borderMm);
  push("Solar Control", u.solarControl);
  push("Tint", u.tint);
  push("Self Cleaning", u.selfCleaning);

  push("Internal Width (mm)", u.widthMm);
  push("Internal Height (mm)", u.heightMm);

  push("External Width (mm)", u.extWidthMm);
  push("External Height (mm)", u.extHeightMm);

  if (safeNum(u.unitPrice) > 0) push("Unit Price", `£${money2(u.unitPrice)}`);
  if (safeNum(u.lineTotal) > 0) push("Line Total", `£${money2(u.lineTotal)}`);

  return attrs;
}

function buildDraftOrderLineItems({ calculatorType, units }) {
  const anchor = pickAnchor(calculatorType);

  // Anchor line item: provides the product image/title in checkout.
  // We discount it 100% so it doesn't affect totals.
  const lineItems = [
    {
      variantId: anchor.variantId,
      quantity: 1,
      customAttributes: [
        { key: "Calculator", value: anchor.label }, // already capitalised
      ],
      appliedDiscount: {
        description: "Anchor item for image/title",
        value: 100,
        valueType: "PERCENTAGE",
      },
    },
  ];

  const type = String(calculatorType || "").toLowerCase();

  (units || []).forEach((raw, idx) => {
    const u = raw || {};
    const qty = Math.max(1, Math.min(10, Math.floor(safeNum(u.qty, 1))));
    const unitPrice = safeNum(u.unitPrice, 0);
    const lineTotal = safeNum(u.lineTotal, unitPrice * qty);

    const title =
      type === "skylight"
        ? `Skylight Unit ${idx + 1}`
        : `Glazed Unit ${idx + 1}`;

    const customAttributes =
      type === "skylight"
        ? buildSkylightUnitCustomAttributes(u)
        : buildDguUnitCustomAttributes(u);

    // Custom line item: carries the actual price & properties.
    // IMPORTANT: custom line items do NOT have an image, but the anchor provides the image at checkout.
    lineItems.push({
      title: capSentence(title),
      quantity: qty,
      originalUnitPrice: money2(unitPrice),
      customAttributes,
    });

    // If you ever want to force totals to match lineTotal even if unitPrice differs:
    // Shopify Draft Order custom line items are (qty * originalUnitPrice),
    // so we keep originalUnitPrice = unitPrice and lineTotal is informational in attributes.
    void lineTotal;
  });

  return lineItems;
}

function computeGrandTotals(units) {
  const list = Array.isArray(units) ? units : [];
  const totalUnitsQty = list.reduce((sum, u) => sum + Math.max(0, safeNum(u?.qty, 0)), 0);
  const grandTotal = list.reduce((sum, u) => sum + safeNum(u?.lineTotal, 0), 0);

  return {
    totalUnitsQty,
    grandTotal,
  };
}

/* ========= SIGNATURE VERIFY ========= */
function verifySignature(req) {
  const ts = req.get("X-RG-Timestamp");
  const sig = req.get("X-RG-Signature");
  if (!ts || !sig) return { ok: false, reason: "Missing signature headers" };

  const tsNum = Number(ts);
  if (!Number.isFinite(tsNum)) return { ok: false, reason: "Invalid timestamp" };

  const age = Math.abs(Date.now() - tsNum);
  if (age > SIGNATURE_MAX_AGE_MS) return { ok: false, reason: "Signature expired" };

  const rawBody = req.rawBody || "";
  const expected = hmacSha256Hex(FRONTEND_SHARED_SECRET, `${ts}.${rawBody}`);

  // constant-time compare
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(String(sig), "utf8");
  if (a.length !== b.length) return { ok: false, reason: "Signature mismatch" };
  const ok = crypto.timingSafeEqual(a, b);
  return ok ? { ok: true } : { ok: false, reason: "Signature mismatch" };
}

/* ========= ROUTES ========= */
app.get("/", (req, res) => {
  res.json({ ok: true, service: "RightGlaze Draft Order Checkout", version: "server.js unified" });
});

app.post("/checkout", async (req, res) => {
  try {
    // 1) Verify HMAC
    const sigCheck = verifySignature(req);
    if (!sigCheck.ok) {
      return res.status(401).json({ error: "Unauthorized", reason: sigCheck.reason });
    }

    // 2) Validate payload
    const body = req.body || {};
    const calculatorType = String(body.calculatorType || "dgu").toLowerCase();
    const units = Array.isArray(body.units) ? body.units : [];

    if (!units.length) {
      return res.status(400).json({ error: "Bad Request", reason: "No units provided" });
    }

    // 3) Compute totals (this fixes “grand totals not pulling through”)
    const computed = computeGrandTotals(units);
    const grandTotal = computed.grandTotal;
    const totalUnitsQty = safeNum(body.totalUnitsQty, computed.totalUnitsQty);

    // 4) Build line items
    const lineItems = buildDraftOrderLineItems({ calculatorType, units });

    // 5) Note + attributes — shows on draft order / invoice / admin
    const anchor = pickAnchor(calculatorType);

    const noteLines = [
      `Calculator: ${anchor.label}`,                  // Capitalised
      `Total Units: ${totalUnitsQty}`,                // Capitalised
      `Grand Total: £${money2(grandTotal)}`,          // Capitalised
    ];

    const noteAttributes = [
      { name: "Calculator", value: anchor.label },
      { name: "Total Units", value: String(totalUnitsQty) },
      { name: "Grand Total", value: `£${money2(grandTotal)}` },
    ];

    // 6) Create Draft Order
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
        // You can set currencyCode if you want; normally inherited from shop
        // currencyCode: "GBP",
        note: noteLines.join("\n"),
        noteAttributes,
        lineItems,
      },
    };

    const data = await shopifyGraphQL(mutation, variables);

    const errs = data?.draftOrderCreate?.userErrors || [];
    if (errs.length) {
      return res.status(400).json({
        error: "Draft order create failed",
        reason: errs.map((e) => e.message).join(" | "),
        userErrors: errs,
      });
    }

    const invoiceUrl = data?.draftOrderCreate?.draftOrder?.invoiceUrl;
    if (!invoiceUrl) {
      return res.status(500).json({ error: "Checkout created but invoiceUrl missing" });
    }

    // 7) Return
    return res.json({
      ok: true,
      invoiceUrl,
      calculatorType,
      grandTotal: money2(grandTotal),
      totalUnitsQty,
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error", reason: e?.message || String(e) });
  }
});

/* ========= START ========= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`RightGlaze checkout server listening on port ${PORT}`);
});
