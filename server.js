// server.js (ESM)
// ✅ Change applied: Option 2 — apply the anchor variant to EVERY unit line item
// so each unit line gets the product image in checkout, and use priceOverride for bespoke pricing.

import express from "express";
import crypto from "crypto";

const app = express();
app.use(express.json({ limit: "1mb" }));

/* -------------------- ENV -------------------- */
function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const SHOPIFY_SHOP_DOMAIN = mustEnv("SHOPIFY_SHOP_DOMAIN"); // e.g. rightglaze.myshopify.com
const SHOPIFY_ADMIN_ACCESS_TOKEN = mustEnv("SHOPIFY_ADMIN_ACCESS_TOKEN");
const FRONTEND_SHARED_SECRET = mustEnv("FRONTEND_SHARED_SECRET");

// Anchor variants used to “carry” product image in checkout
const ANCHOR_VARIANT_GID_DGU = mustEnv("ANCHOR_VARIANT_GID_DGU");
const ANCHOR_VARIANT_GID_SKYLIGHT = mustEnv("ANCHOR_VARIANT_GID_SKYLIGHT");

// Fixed API version (change if you need)
const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2025-10";
const CURRENCY_CODE = process.env.CURRENCY_CODE || "GBP";

/* -------------------- HELPERS -------------------- */
function roundMoney(n) {
  const x = Number(n);
  if (!Number.isFinite(x)) return 0;
  return Math.round(x * 100) / 100;
}

function safeStr(v) {
  if (v === null || v === undefined) return "";
  return String(v);
}

function makeAttribute(key, value) {
  return { key: safeStr(key), value: safeStr(value) };
}

// Verify HMAC: signature = HMAC(secret, `${ts}.${rawBody}`)
function verifyHmac({ secret, timestamp, signature, rawBody }) {
  if (!timestamp || !signature) return false;

  const payload = `${timestamp}.${rawBody}`;
  const expected = crypto.createHmac("sha256", secret).update(payload).digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(signature, "hex"));
  } catch {
    return false;
  }
}

async function shopifyGraphQL(query, variables) {
  const url = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_ACCESS_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });

  const json = await res.json().catch(() => ({}));

  if (!res.ok) {
    const msg = json?.errors ? JSON.stringify(json.errors) : await res.text().catch(() => "");
    throw new Error(`Shopify GraphQL HTTP ${res.status}: ${msg}`);
  }

  if (json?.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
  }

  return json.data;
}

function calcTypeLabel(calculatorType) {
  const t = String(calculatorType || "").toLowerCase();
  if (t === "dgu") return "DGU";
  if (t === "skylight") return "Skylight";
  return "Calculator";
}

function anchorVariantForType(calculatorType) {
  const t = String(calculatorType || "").toLowerCase();
  if (t === "skylight") return ANCHOR_VARIANT_GID_SKYLIGHT;
  return ANCHOR_VARIANT_GID_DGU;
}

/* Build customAttributes for DGU unit */
function buildDguAttributes(u) {
  const attrs = [];
  attrs.push(makeAttribute("Calculator", "DGU"));
  attrs.push(makeAttribute("Outer Glass", u.outerGlass));
  attrs.push(makeAttribute("Inner Glass", u.innerGlass));
  attrs.push(makeAttribute("Cavity", u.cavityWidth));
  attrs.push(makeAttribute("Size", `${u.widthMm}×${u.heightMm}mm`));
  attrs.push(makeAttribute("Spacer", u.spacer));
  attrs.push(makeAttribute("Self Cleaning", u.selfCleaning));
  attrs.push(makeAttribute("Unit Price", `£${roundMoney(u.unitPrice).toFixed(2)}`));
  attrs.push(makeAttribute("Line Total", `£${roundMoney(u.lineTotal).toFixed(2)}`));
  return attrs;
}

/* Build customAttributes for Skylight unit */
function buildSkylightAttributes(u) {
  const attrs = [];
  attrs.push(makeAttribute("Calculator", "Skylight"));
  attrs.push(makeAttribute("Unit Strength", u.unitStrength));
  attrs.push(makeAttribute("Glazing", u.glazing));
  if (u.borderMm) attrs.push(makeAttribute("Border", `${u.borderMm}mm`));

  // Use your existing orientation (your screenshot shows "Internal 500x800mm")
  attrs.push(makeAttribute("Internal", `${u.widthMm}×${u.heightMm}mm`));
  if (u.extWidthMm && u.extHeightMm) {
    attrs.push(makeAttribute("External", `${u.extWidthMm}×${u.extHeightMm}mm`));
  }

  attrs.push(makeAttribute("Tint", u.tint));
  attrs.push(makeAttribute("Solar Control", u.solarControl));
  attrs.push(makeAttribute("Self Cleaning", u.selfCleaning));

  attrs.push(makeAttribute("Unit Price", `£${roundMoney(u.unitPrice).toFixed(2)}`));
  attrs.push(makeAttribute("Line Total", `£${roundMoney(u.lineTotal).toFixed(2)}`));
  return attrs;
}

/* ✅ Core change: every unit becomes a VARIANT line item (image comes from product),
   and priceOverride sets bespoke unit price. */
function buildDraftLineItemsFromUnits({ calculatorType, units }) {
  const anchorVariantId = anchorVariantForType(calculatorType);
  const label = calcTypeLabel(calculatorType);

  return (units || []).map((u, idx) => {
    const qty = Math.max(1, Number(u.qty) || 1);
    const unitPrice = roundMoney(u.unitPrice);

    const customAttributes =
      String(calculatorType || "").toLowerCase() === "skylight"
        ? buildSkylightAttributes(u)
        : buildDguAttributes(u);

    return {
      variantId: anchorVariantId,
      quantity: qty,

      // ✅ Bespoke pricing
      priceOverride: {
        amount: unitPrice.toFixed(2),
        currencyCode: CURRENCY_CODE,
      },

      // Optional: unique id per line
      uuid: `${label.toLowerCase()}-${Date.now()}-${idx}-${Math.random().toString(16).slice(2)}`,

      customAttributes,
    };
  });
}

function sumLineTotals(units) {
  return roundMoney(
    (units || []).reduce((sum, u) => sum + (Number(u.lineTotal) || 0), 0)
  );
}

/* -------------------- ROUTES -------------------- */
app.get("/", (_req, res) => res.status(200).send("OK"));

app.post("/checkout", async (req, res) => {
  try {
    const ts = req.header("X-RG-Timestamp");
    const sig = req.header("X-RG-Signature");

    const rawBody = JSON.stringify(req.body ?? {});
    const ok = verifyHmac({
      secret: FRONTEND_SHARED_SECRET,
      timestamp: ts,
      signature: sig,
      rawBody,
    });

    if (!ok) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const body = req.body || {};
    const calculatorType = body.calculatorType; // "dgu" | "skylight"
    const units = Array.isArray(body.units) ? body.units : [];

    if (!units.length) {
      return res.status(400).json({ error: "No units provided" });
    }

    // Prefer grandTotal sent by frontend, fallback to summing line totals.
    const providedGrand = roundMoney(body.grandTotal);
    const computedGrand = sumLineTotals(units);
    const grandTotal = providedGrand > 0 ? providedGrand : computedGrand;

    const lineItems = buildDraftLineItemsFromUnits({ calculatorType, units });

    // Draft note: helps you see totals/type in admin
    const note = `Calculator: ${calcTypeLabel(calculatorType)} | Grand Total: £${grandTotal.toFixed(
      2
    )}`;

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
        lineItems,
        note,
      },
    };

    const data = await shopifyGraphQL(mutation, variables);

    const userErrors = data?.draftOrderCreate?.userErrors || [];
    if (userErrors.length) {
      return res.status(400).json({
        error: "Shopify draftOrderCreate userErrors",
        reason: userErrors.map((e) => e.message).join("; "),
      });
    }

    const invoiceUrl = data?.draftOrderCreate?.draftOrder?.invoiceUrl;
    if (!invoiceUrl) {
      return res.status(500).json({ error: "Draft created but invoiceUrl missing" });
    }

    return res.status(200).json({ invoiceUrl });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Server error",
      reason: err?.message || String(err),
    });
  }
});

/* -------------------- START -------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Draft order app listening on port ${PORT}`);
});
