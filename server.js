/**
 * RightGlaze Draft Order Checkout Server (Render / Node 18+)
 *
 * What this does:
 * - Receives calculator payloads from your Shopify product-page calculators
 * - Verifies HMAC signature (FRONTEND_SHARED_SECRET) to prevent tampering
 * - Creates a Shopify Draft Order using an "anchor" variant so checkout shows the correct product image/title
 * - Pushes GRAND TOTAL to checkout by overriding the anchor line item price to the calculator grand total
 * - Stores full breakdown in Draft Order note + custom attributes (with Capitalised labels)
 *
 * Required env vars (Render -> Environment):
 * - SHOPIFY_SHOP_DOMAIN             e.g. rightglaze.myshopify.com  (NO https)
 * - SHOPIFY_ADMIN_ACCESS_TOKEN      shpat_...
 * - FRONTEND_SHARED_SECRET          must match the calculators
 * - DGU_ANCHOR_VARIANT_GID          gid://shopify/ProductVariant/...
 * - SKYLIGHT_ANCHOR_VARIANT_GID     gid://shopify/ProductVariant/...
 *
 * Optional:
 * - SHOPIFY_API_VERSION             e.g. 2024-10 (default below)
 * - PORT                            (Render sets this)
 */

import express from "express";
import crypto from "crypto";

const app = express();

/* ----------------------------- ENV + VALIDATION ---------------------------- */

function mustEnv(name, value) {
  if (!value || String(value).trim() === "") {
    throw new Error(`Missing required env var: ${name}`);
  }
}

const SHOPIFY_SHOP_DOMAIN = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_ADMIN_ACCESS_TOKEN = process.env.SHOPIFY_ADMIN_ACCESS_TOKEN;
const FRONTEND_SHARED_SECRET = process.env.FRONTEND_SHARED_SECRET;

const DGU_ANCHOR_VARIANT_GID = process.env.DGU_ANCHOR_VARIANT_GID;
const SKYLIGHT_ANCHOR_VARIANT_GID = process.env.SKYLIGHT_ANCHOR_VARIANT_GID;

const SHOPIFY_API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-10";

mustEnv("SHOPIFY_SHOP_DOMAIN", SHOPIFY_SHOP_DOMAIN);
mustEnv("SHOPIFY_ADMIN_ACCESS_TOKEN", SHOPIFY_ADMIN_ACCESS_TOKEN);
mustEnv("FRONTEND_SHARED_SECRET", FRONTEND_SHARED_SECRET);
mustEnv("DGU_ANCHOR_VARIANT_GID", DGU_ANCHOR_VARIANT_GID);
mustEnv("SKYLIGHT_ANCHOR_VARIANT_GID", SKYLIGHT_ANCHOR_VARIANT_GID);

/* ----------------------------- BODY (RAW CAPTURE) -------------------------- */
/**
 * We need the raw JSON string exactly as sent so that:
 * signature = HMAC_SHA256(secret, `${timestamp}.${rawBody}`)
 */
app.use(
  express.json({
    limit: "1mb",
    verify: (req, _res, buf) => {
      req.rawBody = buf?.toString("utf8") || "";
    },
  })
);

/* ----------------------------- CORS (simple) ------------------------------- */
/**
 * If you're calling this from Shopify storefront, allow it.
 * If you want to lock it down further, restrict origins to your domains.
 */
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, X-RG-Timestamp, X-RG-Signature");
  res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

/* -------------------------------- UTILITIES -------------------------------- */

function safeNum(n, fallback = 0) {
  const x = typeof n === "string" ? Number(n) : n;
  return Number.isFinite(x) ? x : fallback;
}

function clamp(n, min, max) {
  return Math.min(max, Math.max(min, n));
}

function money2(n) {
  return (Math.round(safeNum(n, 0) * 100) / 100).toFixed(2);
}

function hmacHex(secret, message) {
  return crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
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

function titleCaseLabel(s) {
  // For keys like "outerGlass" or "extWidthMm" -> "Outer Glass" / "Ext Width Mm"
  const str = String(s || "");
  if (!str) return "";
  const spaced = str
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ")
    .trim();
  return spaced
    .split(/\s+/)
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : ""))
    .join(" ");
}

function toCustomAttributes(obj, allowKeys = null) {
  // Shopify DraftOrder customAttributes: [{ key, value }]
  if (!obj || typeof obj !== "object") return [];
  const out = [];
  for (const [k, v] of Object.entries(obj)) {
    if (allowKeys && !allowKeys.has(k)) continue;
    if (v === undefined || v === null) continue;
    const key = titleCaseLabel(k);
    const value = String(v);
    if (!key || !value) continue;
    out.push({ key, value });
  }
  // Shopify has practical limits; keep it sane
  return out.slice(0, 40);
}

function calcGrandTotalFromUnits(units) {
  return (Array.isArray(units) ? units : []).reduce((sum, u) => {
    const lineTotal = safeNum(u?.lineTotal, safeNum(u?.unitPrice, 0) * safeNum(u?.qty, 1));
    return sum + (Number.isFinite(lineTotal) ? lineTotal : 0);
  }, 0);
}

/* ------------------------------ SHOPIFY GRAPHQL ---------------------------- */

const SHOPIFY_GRAPHQL_URL = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

async function shopifyGraphQL(query, variables) {
  const resp = await fetch(SHOPIFY_GRAPHQL_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ADMIN_ACCESS_TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });

  const json = await resp.json().catch(() => null);

  if (!resp.ok) {
    const text = json ? JSON.stringify(json) : await resp.text().catch(() => "");
    throw new Error(`Shopify GraphQL HTTP ${resp.status}: ${text}`);
  }

  if (!json) throw new Error("Shopify GraphQL returned empty response");
  if (json.errors?.length) {
    throw new Error(`Shopify GraphQL errors: ${JSON.stringify(json.errors)}`);
  }

  return json.data;
}

/* ------------------------------ HEALTHCHECK -------------------------------- */

app.get("/health", (_req, res) => {
  res.json({ ok: true });
});

/* -------------------------------- CHECKOUT --------------------------------- */
/**
 * Expected payload from calculators:
 * {
 *   calculatorType: "dgu" | "skylight",
 *   totalUnitsQty: number,
 *   units: [{ qty, unitPrice, lineTotal, ... }]
 * }
 *
 * Headers:
 * - X-RG-Timestamp: ms timestamp string
 * - X-RG-Signature: hex(HMAC_SHA256(secret, `${ts}.${rawBody}`))
 */
app.post("/checkout", async (req, res) => {
  try {
    const ts = String(req.header("X-RG-Timestamp") || "");
    const sig = String(req.header("X-RG-Signature") || "");
    const rawBody = String(req.rawBody || "");

    if (!ts || !sig || !rawBody) {
      return res.status(400).json({ error: "Bad Request", reason: "Missing signature headers or body" });
    }

    // Optional replay window (10 mins)
    const now = Date.now();
    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum) || Math.abs(now - tsNum) > 10 * 60 * 1000) {
      return res.status(401).json({ error: "Unauthorized", reason: "Timestamp out of range" });
    }

    const expected = hmacHex(FRONTEND_SHARED_SECRET, `${ts}.${rawBody}`);
    if (!timingSafeEqualHex(expected, sig)) {
      return res.status(401).json({ error: "Unauthorized", reason: "Invalid signature" });
    }

    const body = req.body || {};
    const calculatorType = String(body.calculatorType || "").toLowerCase();
    const units = Array.isArray(body.units) ? body.units : [];

    if (!["dgu", "skylight"].includes(calculatorType)) {
      return res.status(400).json({ error: "Bad Request", reason: "Invalid calculatorType" });
    }
    if (units.length === 0) {
      return res.status(400).json({ error: "Bad Request", reason: "No units provided" });
    }

    // Compute totals (server is source of truth)
    const grandTotal = calcGrandTotalFromUnits(units);
    const totalUnitsQty = clamp(safeNum(body.totalUnitsQty, 0), 0, 9999);

    if (!(grandTotal > 0)) {
      return res.status(400).json({ error: "Bad Request", reason: "Grand total is zero" });
    }

    // Choose correct anchor variant so CHECKOUT shows correct product image
    const anchorVariantId =
      calculatorType === "dgu" ? DGU_ANCHOR_VARIANT_GID : SKYLIGHT_ANCHOR_VARIANT_GID;

    // Title (capitalised – fixes “Calculator” formatting)
    const checkoutTitle =
      calculatorType === "dgu" ? "Bespoke Glazed Unit Calculator" : "Bespoke Frameless Skylight Calculator";

    // Build a compact note with key totals
    const noteLines = [
      checkoutTitle,
      `Total Units (Qty): ${totalUnitsQty || units.reduce((s, u) => s + safeNum(u?.qty, 0), 0)}`,
      `Grand Total: £${money2(grandTotal)}`,
      "",
      "Units:",
    ];

    units.forEach((u, i) => {
      const qty = clamp(safeNum(u?.qty, 1), 1, 10);
      const unitPrice = safeNum(u?.unitPrice, 0);
      const lineTotal = safeNum(u?.lineTotal, unitPrice * qty);
      const w = u?.widthMm ?? u?.w;
      const h = u?.heightMm ?? u?.h;

      // Keep it readable in Shopify admin
      noteLines.push(
        `#${i + 1} × ${qty} | Unit £${money2(unitPrice)} | Line £${money2(lineTotal)} | ${w ?? "?"}mm × ${h ?? "?"}mm`
      );
    });

    // Store the detailed payload as a string in note too (truncated)
    const rawPayloadString = JSON.stringify(
      { calculatorType, totalUnitsQty, grandTotal: money2(grandTotal), units },
      null,
      0
    );
    noteLines.push("");
    noteLines.push("Payload:");
    noteLines.push(rawPayloadString.slice(0, 3500));

    const note = noteLines.join("\n");

    /**
     * IMPORTANT:
     * This is the key fix for your issues:
     * - GRAND TOTAL not pulling through -> we override the anchor line item price to GRAND TOTAL
     * - PRODUCT PICTURE not pulling through -> we use an anchor VARIANT line item (image comes from product)
     *
     * So checkout shows:
     * - Your skylight (or DGU) product image
     * - Price = calculator grand total
     */
    const lineItemAttributes = [
      { key: "Calculator Type", value: calculatorType.toUpperCase() },
      { key: "Order Total", value: `£${money2(grandTotal)}` },
      { key: "Total Units Qty", value: String(totalUnitsQty || "") },
      { key: "Breakdown", value: rawPayloadString.slice(0, 500) }, // short (Shopify UI friendly)
    ];

    const mutation = /* GraphQL */ `
      mutation DraftOrderCreate($input: DraftOrderInput!) {
        draftOrderCreate(input: $input) {
          draftOrder {
            id
            invoiceUrl
            status
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
        tags: [`RG-${calculatorType.toUpperCase()}`, "Calculator"],
        // A single anchor line item priced to the grand total:
        lineItems: [
          {
            variantId: anchorVariantId,
            quantity: 1,
            // Override price so the checkout total matches calculator total
            originalUnitPrice: money2(grandTotal),
            customAttributes: lineItemAttributes,
          },
        ],
        // Also store summary attributes on the draft order itself (shows in Admin)
        customAttributes: [
          { key: "Calculator", value: checkoutTitle },
          { key: "Calculator Type", value: calculatorType.toUpperCase() },
          { key: "Grand Total", value: `£${money2(grandTotal)}` },
          { key: "Total Units Qty", value: String(totalUnitsQty || "") },
        ],
      },
    };

    const data = await shopifyGraphQL(mutation, variables);

    const out = data?.draftOrderCreate;
    const userErrors = out?.userErrors || [];
    if (userErrors.length) {
      return res.status(400).json({ error: "Shopify error", reason: userErrors.map((e) => e.message).join(" | ") });
    }

    const draftOrder = out?.draftOrder;
    const invoiceUrl = draftOrder?.invoiceUrl;

    if (!invoiceUrl) {
      return res.status(500).json({ error: "Checkout created but invoice URL missing" });
    }

    return res.json({
      ok: true,
      invoiceUrl,
      calculatorType,
      grandTotal: money2(grandTotal),
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: "Server error",
      reason: err?.message || String(err),
    });
  }
});

/* --------------------------------- START ---------------------------------- */

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => {
  console.log(`RightGlaze checkout server listening on port ${PORT}`);
  console.log(`Shop: ${SHOPIFY_SHOP_DOMAIN} | API: ${SHOPIFY_API_VERSION}`);
});
