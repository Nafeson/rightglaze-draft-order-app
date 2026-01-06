import express from "express";
import crypto from "crypto";

const app = express();

/* =========================
RAW BODY (for HMAC)
========================= */
app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buf) => {
      req.rawBody = buf;
    },
  })
);

const {
  SHOPIFY_SHOP,
  SHOPIFY_ADMIN_TOKEN,
  SHOPIFY_API_SECRET, // (not used directly here, but you required it before)
  SHOPIFY_API_VERSION = "2025-10",
  PRESENTMENT_CURRENCY = "GBP",
  PORT = 3000,

  ALLOWED_ORIGIN,
  FRONTEND_SHARED_SECRET,

  // ✅ Separate anchor variants (so checkout shows correct product + image)
  ANCHOR_VARIANT_GID_DGU,
  ANCHOR_VARIANT_GID_SKYLIGHT,
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
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type,X-RG-Timestamp,X-RG-Signature"
  );
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
  const digest = crypto
    .createHmac("sha256", FRONTEND_SHARED_SECRET)
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
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
      },
      body: JSON.stringify({ query, variables }),
    }
  );

  const json = await res.json();
  if (!res.ok || json.errors) throw new Error(JSON.stringify(json));
  return json.data;
}

/* =========================
DGU PRICING (INC VAT)
Unit price = max(minPrice, areaM2*baseRate + areaM2*selfCleanRateIfYes)
========================= */
function bandRate(areaM2, bands) {
  for (const b of bands) {
    if (areaM2 >= b.min && areaM2 <= b.max) return b.rate;
  }
  return 0;
}

const PRICING_TABLES = {
  "4mm Clear|4mm Clear": {
    minPrice: 48.75,
    bands: [
      { min: 0, max: 0.99, rate: 125 }, // includes <0.5 and 0.5–0.99
      { min: 1.0, max: 1.49, rate: 130 },
      { min: 1.5, max: 1.99, rate: 135 },
      { min: 2.0, max: 2.5, rate: 140 },
    ],
  },
  "4mm Clear|4mm Softcoat": {
    minPrice: 48.75,
    bands: [
      { min: 0, max: 0.49, rate: 130 },
      { min: 0.5, max: 0.99, rate: 132 },
      { min: 1.0, max: 1.49, rate: 138 },
      { min: 1.5, max: 1.99, rate: 145 },
      { min: 2.0, max: 2.5, rate: 152 },
    ],
  },
  "6mm Clear|6mm Clear": {
    minPrice: 95.75,
    bands: [
      { min: 0, max: 0.49, rate: 215 },
      { min: 0.5, max: 0.99, rate: 255 },
      { min: 1.0, max: 1.49, rate: 260 },
      { min: 1.5, max: 1.99, rate: 262 },
      { min: 2.0, max: 2.5, rate: 265 },
      { min: 2.51, max: 3.0, rate: 270 },
    ],
  },
  "6mm Clear|6mm Softcoat": {
    minPrice: 127.75,
    bands: [
      { min: 0, max: 0.49, rate: 225 },
      { min: 0.5, max: 0.99, rate: 270 },
      { min: 1.0, max: 1.49, rate: 278 },
      { min: 1.5, max: 1.99, rate: 282 },
      { min: 2.0, max: 2.5, rate: 285 },
      { min: 2.51, max: 3.0, rate: 290 },
    ],
  },
};

const SELF_CLEAN_BANDS = [
  { min: 0, max: 0.49, rate: 30 },
  { min: 0.5, max: 0.99, rate: 38 },
  { min: 1.0, max: 1.49, rate: 42 },
  { min: 1.5, max: 1.99, rate: 45 },
  { min: 2.0, max: 2.5, rate: 48 },
  { min: 2.51, max: 3.0, rate: 52 },
];

function calcUnitPriceIncVatDGU(unit) {
  const { outerGlass, innerGlass, selfCleaning, widthMm, heightMm } = unit;
  if (
    !Number.isFinite(widthMm) ||
    !Number.isFinite(heightMm) ||
    widthMm <= 0 ||
    heightMm <= 0
  )
    return 0;

  const areaM2 = (widthMm * heightMm) / 1_000_000;

  const key = `${outerGlass}|${innerGlass}`;
  const table = PRICING_TABLES[key];
  if (!table) return 0;

  const baseRate = bandRate(areaM2, table.bands);
  if (!baseRate) return 0;

  const selfRate =
    selfCleaning === "Yes" ? bandRate(areaM2, SELF_CLEAN_BANDS) : 0;

  const price = areaM2 * baseRate + areaM2 * selfRate;
  return Math.max(table.minPrice, price);
}

/* =========================
DGU NORMALIZATION / RULES
========================= */
function clampDimsDGU(w, h) {
  const min = 150,
    maxW = 3000,
    maxH = 1732;
  return {
    w: Math.min(maxW, Math.max(min, w)),
    h: Math.min(maxH, Math.max(min, h)),
  };
}

function applyAreaRuleDGU(unit) {
  const area = (unit.widthMm * unit.heightMm) / 1_000_000;
  if (
    area >= 2.5 &&
    unit.outerGlass === "4mm Clear" &&
    unit.innerGlass === "4mm Clear"
  ) {
    return {
      ...unit,
      outerGlass: "6mm Clear",
      innerGlass: "6mm Clear",
      _areaUpgradeApplied: true,
    };
  }
  return { ...unit, _areaUpgradeApplied: false };
}

function normalizeUnitDGU(raw) {
  const { w, h } = clampDimsDGU(Number(raw.widthMm), Number(raw.heightMm));
  return applyAreaRuleDGU({
    qty: Math.min(10, Math.max(1, Number(raw.qty) || 1)),
    outerGlass: String(raw.outerGlass),
    innerGlass: String(raw.innerGlass),
    cavityWidth: String(raw.cavityWidth),
    selfCleaning: String(raw.selfCleaning),
    spacer: String(raw.spacer),
    widthMm: w,
    heightMm: h,
    toughened: "Yes",
  });
}

/* =========================
SKYLIGHT VALIDATION
(We price skylight on the front-end table, then we sanity-check payload here.)
========================= */
function toNum(x) {
  const n = Number(x);
  return Number.isFinite(n) ? n : NaN;
}

function approxEqualMoney(a, b, tolerancePounds = 0.05) {
  return Math.abs(a - b) <= tolerancePounds;
}

function normalizeUnitSkylight(raw) {
  const qty = Math.min(10, Math.max(1, Number(raw.qty) || 1));

  // your skylight payload structure (from your script)
  const internalW = toNum(raw?.internal?.widthMm);
  const internalH = toNum(raw?.internal?.heightMm);
  const externalW = toNum(raw?.external?.widthMm);
  const externalH = toNum(raw?.external?.heightMm);

  const unitPrice = toNum(raw?.unitPrice);
  const lineTotal = toNum(raw?.lineTotal);

  return {
    qty,
    unitStrength: String(raw?.unitStrength || ""),
    glazing: String(raw?.glazing || ""),
    borderMm: toNum(raw?.borderMm),
    solarControl: String(raw?.solarControl || ""),
    tint: String(raw?.tint || ""),
    selfCleaning: String(raw?.selfCleaning || ""),

    internalW,
    internalH,
    externalW,
    externalH,

    unitPrice,
    lineTotal,
  };
}

function validateSkylightUnit(u) {
  // internal dimension rules from your skylight script
  if (!Number.isFinite(u.internalW) || !Number.isFinite(u.internalH)) return false;
  if (u.internalW < 300 || u.internalW > 2000) return false;
  if (u.internalH < 300 || u.internalH > 1200) return false;

  // wide rule: if width > 1800 then height >= 600
  if (u.internalW > 1800 && u.internalH < 600) return false;

  // 3m² rule
  const areaMm2 = u.internalW * u.internalH;
  if (!(areaMm2 > 0) || areaMm2 > 3_000_000) return false;

  // price sanity
  if (!Number.isFinite(u.unitPrice) || u.unitPrice <= 0) return false;
  if (!Number.isFinite(u.lineTotal) || u.lineTotal <= 0) return false;

  // line total should match unitPrice * qty (within a few pence)
  const expected = u.unitPrice * u.qty;
  if (!approxEqualMoney(u.lineTotal, expected, 0.10)) return false;

  return true;
}

/* =========================
CHECKOUT
========================= */
app.post("/checkout", async (req, res) => {
  try {
    const origin = req.headers.origin || "";
    if (origin !== ALLOWED_ORIGIN)
      return res.status(403).json({ error: "Forbidden" });
    setCors(res, origin);

    if (!verifyFrontendSignature(req)) {
      return res.status(401).json({ error: "Invalid signature" });
    }

    const calculatorTypeRaw = String(req.body?.calculatorType || "").toLowerCase();
    const calculatorType =
      calculatorTypeRaw === "skylight" ? "skylight" : "dgu"; // default to dgu

    let grandTotal = 0;
    let totalUnits = 0;

    // Values used to create the Draft Order line item
    let lineTitle = "Bespoke Double Glazed Units";
    let anchorVariantId = ANCHOR_VARIANT_GID_DGU || null;

    if (calculatorType === "skylight") {
      lineTitle = "Bespoke Frameless Skylight";
      anchorVariantId = ANCHOR_VARIANT_GID_SKYLIGHT || null;

      const unitsRaw = req.body?.units;
      if (!Array.isArray(unitsRaw) || !unitsRaw.length) {
        return res.status(400).json({ error: "Missing units" });
      }

      const units = unitsRaw.map(normalizeUnitSkylight);

      for (const u of units) {
        if (!validateSkylightUnit(u)) {
          return res.status(422).json({ error: "Unpriced configuration" });
        }
        totalUnits += u.qty;
        grandTotal += u.lineTotal;
      }
    } else {
      // DGU (server-priced)
      const unitsRaw = req.body?.units;
      if (!Array.isArray(unitsRaw) || !unitsRaw.length) {
        return res.status(400).json({ error: "Missing units" });
      }

      const units = unitsRaw.map(normalizeUnitDGU);

      for (const u of units) {
        const unitPrice = calcUnitPriceIncVatDGU(u);
        u._unitPriceIncVat = unitPrice;
        grandTotal += unitPrice * u.qty;
      }

      if (grandTotal <= 0) {
        return res.status(422).json({ error: "Unpriced configuration" });
      }

      // total number of units INCLUDING qty
      totalUnits = units.reduce((sum, u) => sum + (Number(u.qty) || 0), 0);
    }

    // round grand total to pennies
    grandTotal = Number(grandTotal.toFixed(2));

    if (!(grandTotal > 0) || !(totalUnits > 0)) {
      return res.status(422).json({ error: "Unpriced configuration" });
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
      lineItems: [
        {
          title: lineTitle,
          quantity: 1,
          requiresShipping: true,
          taxable: true,
          variantId: anchorVariantId,
          priceOverride: {
            amount: grandTotal.toFixed(2),
            currencyCode: PRESENTMENT_CURRENCY,
          },
          customAttributes: [
            { key: "Calculator", value: calculatorType },
            { key: "No. of Units", value: String(totalUnits) },
            { key: "Grand Total (inc VAT)", value: `£${grandTotal.toFixed(2)}` },
          ],
        },
      ],
    };

    const data = await shopifyGraphQL(mutation, { input });

    const userErrors = data?.draftOrderCreate?.userErrors || [];
    if (userErrors.length) {
      return res.status(422).json({
        error: "Shopify user error",
        reason: userErrors.map((e) => e.message).join(" | "),
      });
    }

    const draft = data?.draftOrderCreate?.draftOrder;
    if (!draft?.invoiceUrl) {
      return res.status(500).json({ error: "Missing invoiceUrl from Shopify" });
    }

    return res.json({
      invoiceUrl: draft.invoiceUrl,
      grandTotal,
      calculatorType,
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
