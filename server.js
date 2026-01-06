import express from "express";
import crypto from "crypto";

const app = express();
app.set("trust proxy", 1);

/* =========================
ENV
========================= */
function mustEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const SHOPIFY_SHOP_DOMAIN = mustEnv("SHOPIFY_SHOP_DOMAIN");
const SHOPIFY_ADMIN_ACCESS_TOKEN = mustEnv("SHOPIFY_ADMIN_ACCESS_TOKEN");
const FRONTEND_SHARED_SECRET = mustEnv("FRONTEND_SHARED_SECRET");

const ANCHOR_VARIANT_GID_DGU = mustEnv("ANCHOR_VARIANT_GID_DGU");
const ANCHOR_VARIANT_GID_SKYLIGHT = mustEnv("ANCHOR_VARIANT_GID_SKYLIGHT");

/* =========================
CORS / PREFLIGHT
========================= */
function setCors(req, res) {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,X-RG-Timestamp,X-RG-Signature"
  );
}

app.options("/checkout", (req, res) => {
  setCors(req, res);
  res.status(204).end();
});

/* =========================
RAW BODY (for HMAC)
========================= */
app.post("/checkout", express.raw({ type: "application/json", limit: "1mb" }));

/* =========================
HMAC VERIFY
========================= */
function timingSafeEqualHex(a, b) {
  const ba = Buffer.from(a, "hex");
  const bb = Buffer.from(b, "hex");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function verifySignature(req, rawBody) {
  const ts = req.header("X-RG-Timestamp");
  const sig = req.header("X-RG-Signature");
  if (!ts || !sig) return false;

  const payload = `${ts}.${rawBody}`;
  const expected = crypto
    .createHmac("sha256", FRONTEND_SHARED_SECRET)
    .update(payload)
    .digest("hex");

  return timingSafeEqualHex(expected, sig);
}

/* =========================
SHOPIFY GRAPHQL
========================= */
async function shopifyGraphql(query, variables) {
  const res = await fetch(
    `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-01/graphql.json`,
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
    throw new Error(
      `Shopify GraphQL error: ${JSON.stringify(json.errors || json)}`
    );
  }
  return json.data;
}

/* =========================
HELPERS
========================= */
function pickAnchorVariant(type) {
  return String(type).toLowerCase() === "skylight"
    ? ANCHOR_VARIANT_GID_SKYLIGHT
    : ANCHOR_VARIANT_GID_DGU;
}

function money(n) {
  return Number(n).toFixed(2);
}

/* =========================
BUILD LINE ITEMS
(Updates:
 - Size attribute FIRST
 - Size always Height × Width
)
========================= */
function buildLineItems(calculatorType, units) {
  const variantId = pickAnchorVariant(calculatorType);
  const type = String(calculatorType).toUpperCase();

  return units.map((u) => {
    const qty = Math.max(1, Number(u.qty) || 1);
    const unitPrice = Number(u.unitPrice) || 0;

    const customAttributes = [];

    if (type === "DGU") {
      // ✅ Size FIRST, and Height first in value
      customAttributes.push({
        key: "Size",
        value: `${u.heightMm}mm × ${u.widthMm}mm`,
      });

      customAttributes.push(
        { key: "Calculator", value: type },
        { key: "Outer Glass", value: u.outerGlass },
        { key: "Inner Glass", value: u.innerGlass },
        { key: "Cavity", value: u.cavityWidth },
        { key: "Spacer", value: u.spacer },
        { key: "Self Cleaning", value: u.selfCleaning }
      );
    } else {
      // ✅ Size FIRST, and Height first in value (Internal size first)
      customAttributes.push({
        key: "Size",
        value: `${u.heightMm}mm × ${u.widthMm}mm (Internal)`,
      });

      customAttributes.push(
        { key: "Calculator", value: type },
        { key: "Unit Strength", value: u.unitStrength },
        { key: "Glazing", value: u.glazing },
        { key: "Tint", value: u.tint },
        { key: "Solar Control", value: u.solarControl },
        { key: "Self Cleaning", value: u.selfCleaning },
        {
          key: "External",
          value: `${u.extHeightMm}mm × ${u.extWidthMm}mm`,
        }
      );
    }

    return {
      variantId,
      quantity: qty,
      originalUnitPrice: money(unitPrice),
      customAttributes,
    };
  });
}

/* =========================
CHECKOUT
========================= */
app.post("/checkout", async (req, res) => {
  try {
    setCors(req, res);

    const rawBody = req.body.toString("utf8");
    if (!verifySignature(req, rawBody)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const payload = JSON.parse(rawBody);
    const { calculatorType, units } = payload;

    if (!Array.isArray(units) || units.length === 0) {
      return res.status(400).json({ error: "No units supplied" });
    }

    const lineItems = buildLineItems(calculatorType, units);

    const mutation = `
      mutation draftOrderCreate($input: DraftOrderInput!) {
        draftOrderCreate(input: $input) {
          draftOrder {
            id
            invoiceUrl
          }
          userErrors { message }
        }
      }
    `;

    const input = {
      lineItems,
      tags: [`calculator:${calculatorType}`],
    };

    const data = await shopifyGraphql(mutation, { input });
    const draft = data.draftOrderCreate.draftOrder;

    return res.json({ invoiceUrl: draft.invoiceUrl });
  } catch (err) {
    console.error("Server error", err);
    res.status(500).json({ error: "Server error" });
  }
});

/* =========================
START
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`RightGlaze checkout server running on ${PORT}`)
);
