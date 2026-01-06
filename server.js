// server.js (ESM)
// RightGlaze Draft Order checkout service (Render)
//
// Adds: ✅ CORS + preflight (OPTIONS) support for custom headers (X-RG-*)
// Keeps: HMAC verification + calculatorType routing (DGU vs Skylight) + anchor variant image

import express from "express";
import crypto from "crypto";

const app = express();

// ---------- helpers ----------
function mustEnv(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) throw new Error(`Missing required env var: ${name}`);
  return String(v).trim();
}

function optEnv(name, fallback = "") {
  const v = process.env[name];
  return (v == null || !String(v).trim()) ? fallback : String(v).trim();
}

function money(n) {
  const x = Number(n);
  return Number.isFinite(x) ? x.toFixed(2) : "0.00";
}

function safeStr(x) {
  return String(x ?? "").trim();
}

function sha256HmacHex(secret, message) {
  return crypto.createHmac("sha256", secret).update(message, "utf8").digest("hex");
}

function timingSafeEqualHex(a, b) {
  const aa = Buffer.from(String(a || ""), "hex");
  const bb = Buffer.from(String(b || ""), "hex");
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function calcGrandTotalFromUnits(units = []) {
  return units.reduce((sum, u) => sum + (Number(u?.lineTotal) || 0), 0);
}

function pickAnchorVariantGid(calculatorType) {
  const t = String(calculatorType || "").toLowerCase();
  if (t === "skylight") return mustEnv("ANCHOR_VARIANT_GID_SKYLIGHT");
  if (t === "dgu") return mustEnv("ANCHOR_VARIANT_GID_DGU");
  // default to DGU if unknown, but better to be explicit
  return mustEnv("ANCHOR_VARIANT_GID_DGU");
}

function buildDraftTitle(calculatorType) {
  const t = String(calculatorType || "").toLowerCase();
  if (t === "skylight") return "Bespoke Frameless Skylight";
  if (t === "dgu") return "Bespoke Double Glazed Unit";
  return "Bespoke Calculator Order";
}

// Pretty, capitalised keys in the checkout “line item properties” + draft order note
function buildUnitLines(calculatorType, u) {
  const t = String(calculatorType || "").toLowerCase();

  if (t === "skylight") {
    const h = Number(u?.heightMm);
    const w = Number(u?.widthMm);
    const eh = Number(u?.extHeightMm);
    const ew = Number(u?.extWidthMm);

    const lines = [
      ["Unit Strength", safeStr(u?.unitStrength)],
      ["Glazing", safeStr(u?.glazing)],
      ["Border", safeStr(u?.borderMm) ? `${safeStr(u?.borderMm)}mm` : safeStr(u?.border)],
      ["Solar Control", safeStr(u?.solarControl)],
      ["Tint", safeStr(u?.tint)],
      ["Self Cleaning", safeStr(u?.selfCleaning)],
      ["Internal Height (mm)", Number.isFinite(h) ? String(h) : ""],
      ["Internal Width (mm)", Number.isFinite(w) ? String(w) : ""],
      ["External Height (mm)", Number.isFinite(eh) ? String(eh) : ""],
      ["External Width (mm)", Number.isFinite(ew) ? String(ew) : ""],
      ["Unit Price (£)", money(u?.unitPrice)],
      ["Line Total (£)", money(u?.lineTotal)],
    ];

    return lines.filter(([k, v]) => safeStr(v) !== "").map(([k, v]) => `${k}: ${v}`);
  }

  // DGU
  const h = Number(u?.heightMm);
  const w = Number(u?.widthMm);
  const lines = [
    ["Outer Glass", safeStr(u?.outerGlass)],
    ["Inner Glass", safeStr(u?.innerGlass)],
    ["Cavity Width", safeStr(u?.cavityWidth)],
    ["Self Cleaning", safeStr(u?.selfCleaning)],
    ["Spacer", safeStr(u?.spacer)],
    ["Height (mm)", Number.isFinite(h) ? String(h) : ""],
    ["Width (mm)", Number.isFinite(w) ? String(w) : ""],
    ["Unit Price (£)", money(u?.unitPrice)],
    ["Line Total (£)", money(u?.lineTotal)],
  ];

  return lines.filter(([k, v]) => safeStr(v) !== "").map(([k, v]) => `${k}: ${v}`);
}

function buildDraftNote(calculatorType, payload, computedGrandTotal) {
  const t = String(calculatorType || "").toLowerCase();
  const title = buildDraftTitle(t);

  const lines = [];
  lines.push(`${title}`);
  lines.push(`Calculator Type: ${t === "skylight" ? "Skylight" : "DGU"}`);
  lines.push(`Total Units Qty: ${Number(payload?.totalUnitsQty) || 0}`);
  lines.push(`Grand Total (£): ${money(computedGrandTotal)}`);
  lines.push("");
  lines.push("Units:");

  const units = Array.isArray(payload?.units) ? payload.units : [];
  units.forEach((u, idx) => {
    const qty = Math.max(1, Number(u?.qty) || 1);
    lines.push(`- Unit ${idx + 1} × ${qty}`);
    const unitLines = buildUnitLines(t, u);
    unitLines.forEach(l => lines.push(`  ${l}`));
  });

  return lines.join("\n");
}

// ---------- config ----------
const SHOPIFY_SHOP_DOMAIN = mustEnv("SHOPIFY_SHOP_DOMAIN"); // e.g. "rightglaze.myshopify.com"
const SHOPIFY_ADMIN_API_ACCESS_TOKEN = mustEnv("SHOPIFY_ADMIN_API_ACCESS_TOKEN"); // Admin API token
const SHOPIFY_API_VERSION = optEnv("SHOPIFY_API_VERSION", "2024-07");

// Server-side shared secret MUST match the one embedded in your page scripts
const FRONTEND_SHARED_SECRET = mustEnv("FRONTEND_SHARED_SECRET");

// Optional: allow multiple storefront origins (comma-separated) if you prefer env control
// Example: "https://www.rightglaze.co.uk,https://rightglaze.co.uk,https://rightglaze.myshopify.com"
const ALLOWED_ORIGINS_ENV = optEnv("ALLOWED_ORIGINS", "");
const ALLOWED_ORIGINS = new Set(
  ALLOWED_ORIGINS_ENV
    ? ALLOWED_ORIGINS_ENV.split(",").map(s => s.trim()).filter(Boolean)
    : [
        "https://www.rightglaze.co.uk",
        "https://rightglaze.co.uk",
        // add your myshopify domain if you test there:
        // "https://rightglaze.myshopify.com",
      ]
);

// ---------- middleware ----------
app.use(express.json({ limit: "1mb" }));

// ✅ CORS + Preflight fix (needed because you send X-RG-Timestamp + X-RG-Signature headers)
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");

    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, X-RG-Timestamp, X-RG-Signature"
    );
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
  }

  // Preflight request
  if (req.method === "OPTIONS") return res.status(204).end();

  next();
});

// ---------- routes ----------
app.get("/", (req, res) => {
  res.type("text").send("OK");
});

app.post("/checkout", async (req, res) => {
  try {
    // 1) Verify signature
    const ts = safeStr(req.header("X-RG-Timestamp"));
    const sig = safeStr(req.header("X-RG-Signature"));
    if (!ts || !sig) {
      return res.status(401).json({ error: "Unauthorized", reason: "Missing signature headers" });
    }

    // Optional: prevent replay (15 minutes)
    const tsNum = Number(ts);
    if (!Number.isFinite(tsNum)) {
      return res.status(401).json({ error: "Unauthorized", reason: "Invalid timestamp" });
    }
    const ageMs = Math.abs(Date.now() - tsNum);
    if (ageMs > 15 * 60 * 1000) {
      return res.status(401).json({ error: "Unauthorized", reason: "Timestamp expired" });
    }

    const rawBody = JSON.stringify(req.body ?? {});
    const toSign = `${ts}.${rawBody}`;
    const expected = sha256HmacHex(FRONTEND_SHARED_SECRET, toSign);

    if (!timingSafeEqualHex(expected, sig)) {
      return res.status(401).json({ error: "Unauthorized", reason: "Bad signature" });
    }

    // 2) Validate payload
    const payload = req.body || {};
    const calculatorType = String(payload.calculatorType || "").toLowerCase();
    const units = Array.isArray(payload.units) ? payload.units : [];
    if (!calculatorType || (calculatorType !== "dgu" && calculatorType !== "skylight")) {
      return res.status(400).json({ error: "Bad Request", reason: "Invalid calculatorType" });
    }
    if (!units.length) {
      return res.status(400).json({ error: "Bad Request", reason: "No units provided" });
    }

    // 3) Compute totals server-side (don’t trust client)
    const computedGrandTotal = calcGrandTotalFromUnits(units);
    const totalUnitsQty =
      Number(payload.totalUnitsQty) > 0
        ? Number(payload.totalUnitsQty)
        : units.reduce((sum, u) => sum + (Number(u?.qty) || 0), 0);

    // 4) Build Draft Order line items
    const anchorVariantId = pickAnchorVariantGid(calculatorType);

    // Anchor line item: this is what gives you product image on checkout
    // We set quantity 1 and price 0.00 so it doesn’t affect totals.
    const lineItems = [
      {
        variantId: anchorVariantId,
        quantity: 1,
        // Keep it free — just for image/title presence
        // If you prefer to hide it from totals, price override 0:
        // Note: Shopify uses "originalUnitPrice" for variant line items
        originalUnitPrice: "0.00",
        customAttributes: [{ key: "Type", value: "Anchor" }],
      },
    ];

    // Add each confirmed unit as a custom line item priced by its lineTotal/qty
    // We price per-unit and set quantity = qty so Shopify totals match.
    units.forEach((u, idx) => {
      const qty = Math.max(1, Math.min(10, Number(u?.qty) || 1));
      const unitPrice = Number(u?.unitPrice) || 0;
      const lineTotal = Number(u?.lineTotal) || (unitPrice * qty);

      // price per item:
      const perItem = qty > 0 ? (lineTotal / qty) : lineTotal;

      const attrs = buildUnitLines(calculatorType, {
        ...u,
        unitPrice,
        lineTotal,
      }).map(s => {
        const [k, ...rest] = s.split(":");
        return { key: safeStr(k), value: safeStr(rest.join(":")) };
      });

      // Add explicit labels that Shopify shows nicely
      attrs.unshift({ key: "Calculator", value: calculatorType === "skylight" ? "Skylight" : "DGU" });
      attrs.unshift({ key: "Unit", value: String(idx + 1) });

      lineItems.push({
        customLineItem: {
          title: `${buildDraftTitle(calculatorType)} — Unit ${idx + 1}`,
          quantity: qty,
          originalUnitPrice: money(perItem),
          customAttributes: attrs,
        },
      });
    });

    // 5) Draft Order note + tags
    const note = buildDraftNote(calculatorType, { ...payload, totalUnitsQty }, computedGrandTotal);

    const draftTitle = buildDraftTitle(calculatorType);

    // 6) Create Draft Order (Shopify Admin GraphQL)
    const endpoint = `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;

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
      note,
      tags: [`Calculator`, calculatorType === "skylight" ? "Skylight" : "DGU"],
      lineItems,
      // If you want, you can set:
      // email, shippingAddress, etc. later
    };

    const gqlRes = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_API_ACCESS_TOKEN,
      },
      body: JSON.stringify({ query: mutation, variables: { input } }),
    });

    const gqlJson = await gqlRes.json().catch(() => ({}));

    if (!gqlRes.ok) {
      const details = gqlJson?.errors ? JSON.stringify(gqlJson.errors) : gqlRes.statusText;
      return res.status(502).json({
        error: `Shopify GraphQL HTTP ${gqlRes.status}`,
        reason: details,
      });
    }

    const userErrors = gqlJson?.data?.draftOrderCreate?.userErrors || [];
    if (userErrors.length) {
      return res.status(400).json({
        error: "Shopify error",
        reason: userErrors.map(e => e.message).join(" | "),
      });
    }

    const invoiceUrl = gqlJson?.data?.draftOrderCreate?.draftOrder?.invoiceUrl;
    if (!invoiceUrl) {
      return res.status(500).json({ error: "Checkout created but invoice URL missing." });
    }

    return res.json({
      invoiceUrl,
      computedGrandTotal: Number(money(computedGrandTotal)),
      totalUnitsQty,
      draftTitle,
    });
  } catch (err) {
    console.error("Checkout error:", err);
    return res.status(500).json({ error: "Server error", reason: err?.message || "Unknown error" });
  }
});

// ---------- start ----------
const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, () => console.log(`Server listening on :${PORT}`));
