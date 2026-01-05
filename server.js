import express from "express";
import crypto from "crypto";

const app = express();

/* =========================
RAW BODY (for HMAC)
========================= */
app.use(express.json({
  limit: "1mb",
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const {
  SHOPIFY_SHOP,
  SHOPIFY_ADMIN_TOKEN,
  SHOPIFY_API_SECRET,
  SHOPIFY_API_VERSION = "2025-10",
  PRESENTMENT_CURRENCY = "GBP",
  PORT = 3000,

  ALLOWED_ORIGIN,
  FRONTEND_SHARED_SECRET,

  // Optional: anchor variant for checkout image
  ANCHOR_VARIANT_GID
} = process.env;

if (!SHOPIFY_SHOP || !SHOPIFY_ADMIN_TOKEN || !SHOPIFY_API_SECRET) {
  console.error("Missing Shopify env vars");
  process.exit(1);
}
if (!ALLOWED_ORIGIN || !FRONTEND_SHARED_SECRET) {
  console.error("Missing frontend security env vars");
  process.exit(1);
}

/* =========================
CORS
========================= */
function setCors(res, origin) {
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Vary", "Origin");
  res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,X-RG-Timestamp,X-RG-Signature");
}

app.options("/checkout", (req, res) => {
  const origin = req.headers.origin || "";
  if (origin === ALLOWED_ORIGIN) setCors(res, origin);
  return res.status(204).end();
});

/* =========================
HMAC VERIFICATION
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
  if (!ts || !sig) return false;

  const raw = req.rawBody.toString("utf8");
  const payload = `${ts}.${raw}`;
  const digest = crypto.createHmac("sha256", FRONTEND_SHARED_SECRET)
    .update(payload)
    .digest("hex");

  return timingSafeEqualHex(sig, digest);
}

/* =========================
SHOPIFY GRAPHQL
========================= */
async function shopifyGraphQL(query, variables) {
  const res = await fetch(
    `https://${SHOPIFY_SHOP}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN
      },
      body: JSON.stringify({ query, variables })
    }
  );

  const json = await res.json();
  if (!res.ok || json.errors) throw new Error(JSON.stringify(json));
  return json.data;
}

/* =========================
CHECKOUT
========================= */
app.post("/checkout", async (req, res) => {
  try {
    const origin = req.headers.origin || "";
    if (origin !== ALLOWED_ORIGIN) {
      return res.status(403).json({ error: "Forbidden" });
    }
    setCors(res, origin);

    if (!verifyFrontendSignature(req)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const { calculatorType, units } = req.body || {};
    if (!Array.isArray(units) || !units.length) {
      return res.status(400).json({ error: "Missing units" });
    }

    /* ======================================================
       SKYLIGHT CALCULATOR (FRONTEND-PRICED)
    ====================================================== */
    if (calculatorType === "skylight") {
      let grandTotal = 0;
      let totalUnits = 0;

      for (const u of units) {
        const qty = Number(u.qty) || 0;
        const unitPrice = Number(u.unitPrice) || 0;

        if (qty <= 0 || unitPrice <= 0) {
          return res.status(422).json({ error: "Unpriced configuration" });
        }

        grandTotal += unitPrice * qty;
        totalUnits += qty;
      }

      const mutation = `
        mutation draftOrderCreate($input: DraftOrderInput!) {
          draftOrderCreate(input: $input) {
            draftOrder { id invoiceUrl }
            userErrors { message }
          }
        }
      `;

      const input = {
        presentmentCurrencyCode: PRESENTMENT_CURRENCY,
        lineItems: [{
          title: "Bespoke Frameless Skylights",
          quantity: 1,
          requiresShipping: true,
          taxable: true,
          variantId: ANCHOR_VARIANT_GID || null,
          priceOverride: {
            amount: grandTotal.toFixed(2),
            currencyCode: PRESENTMENT_CURRENCY
          },
          customAttributes: [
            { key: "Calculator", value: "Skylight" },
            { key: "No. of Units", value: String(totalUnits) },
            { key: "Grand Total (inc VAT)", value: `£${grandTotal.toFixed(2)}` }
          ]
        }]
      };

      const data = await shopifyGraphQL(mutation, { input });
      const draft = data.draftOrderCreate.draftOrder;

      return res.json({
        invoiceUrl: draft.invoiceUrl,
        grandTotal: Number(grandTotal.toFixed(2))
      });
    }

    /* ======================================================
       DGU CALCULATOR (LEGACY – UNCHANGED)
    ====================================================== */
    return res.status(422).json({
      error: "Unpriced configuration",
      reason: "Unknown calculator type"
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
});

app.get("/health", (_, res) => res.json({ ok: true }));

app.listen(PORT, () =>
  console.log(`RightGlaze draft order app listening on ${PORT}`)
);
