// server.js (ESM)
// RightGlaze Draft Order app — DGU + Skylight
// ✔ Correct prices via priceOverride
// ✔ Correct quantity badge
// ✔ Multiline checkout summary
// ✔ Grand total persisted
// ✔ External line added LAST for skylight summary

import express from "express";
import cors from "cors";
import crypto from "crypto";

const app = express();

/* =========================
   ENV
========================= */
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

const PRESENTMENT_CURRENCY_CODE = (process.env.PRESENTMENT_CURRENCY_CODE || "GBP").trim();

/* =========================
   CORS / BODY
========================= */
app.use(cors({ origin: "*", methods: ["GET","POST","OPTIONS"] }));
app.options("*", cors());

app.use(express.json({
  limit: "1mb",
  verify: (req, res, buf) => { req.rawBody = buf.toString("utf8"); }
}));

/* =========================
   SECURITY
========================= */
function hmacSha256Hex(secret, msg){
  return crypto.createHmac("sha256", secret).update(msg).digest("hex");
}

function requireValidSignature(req){
  const ts = req.header("X-RG-Timestamp");
  const sig = req.header("X-RG-Signature");
  if (!ts || !sig) throw new Error("Missing signature headers");

  const expected = hmacSha256Hex(
    FRONTEND_SHARED_SECRET,
    `${ts}.${req.rawBody}`
  );

  if (!crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig))){
    throw new Error("Invalid signature");
  }
}

/* =========================
   HELPERS
========================= */
const money = n => ({
  amount: Number(n || 0).toFixed(2),
  currencyCode: PRESENTMENT_CURRENCY_CODE
});

const fmtGBP = n => `£${Number(n || 0).toFixed(2)}`;

const dimsHW = (h, w) =>
  (Number.isFinite(h) && Number.isFinite(w)) ? `${h}mm × ${w}mm` : "—";

const grandTotalFromUnits = units =>
  units.reduce((s,u)=>s + (Number(u.lineTotal)||0), 0);

/* =========================
   SUMMARY BUILDERS
========================= */

// DGU unchanged
function buildDguAttributes(u){
  const a = [];
  a.push({ key:"Size", value:dimsHW(u.heightMm ?? u.h, u.widthMm ?? u.w) });
  a.push({ key:"Outer Glass", value:u.outerGlass });
  a.push({ key:"Inner Glass", value:u.innerGlass });

  if (u.qty > 1)
    a.push({ key:"Unit Price", value:fmtGBP(u.unitPrice) });

  a.push({ key:"Line Total", value:fmtGBP(u.lineTotal) });
  return a;
}

// Skylight — External added LAST
function buildSkylightAttributes(u){
  const a = [];

  a.push({ key:"Calculator", value:"Skylight" });
  a.push({ key:"Internal", value:dimsHW(u.h, u.w) });
  a.push({ key:"Unit Strength", value:u.unitStrength });
  a.push({ key:"Glazing", value:u.glazing });
  a.push({ key:"Tint", value:u.tint });

  if (String(u.solarControl).toLowerCase() === "yes")
    a.push({ key:"Solar Control", value:"Yes" });

  if (String(u.selfCleaning).toLowerCase() === "yes")
    a.push({ key:"Self Cleaning", value:"Yes" });

  if (u.qty > 1)
    a.push({ key:"Unit Price", value:fmtGBP(u.unitPrice) });

  a.push({ key:"Line Total", value:fmtGBP(u.lineTotal) });

  // ✅ NEW — external ALWAYS LAST
  if (Number.isFinite(u.extH) && Number.isFinite(u.extW)){
    a.push({
      key: "External",
      value: dimsHW(u.extH, u.extW)
    });
  }

  return a;
}

/* =========================
   SHOPIFY GRAPHQL
========================= */
async function shopifyGraphql(query, variables){
  const res = await fetch(
    `https://${SHOPIFY_SHOP_DOMAIN}/admin/api/2025-10/graphql.json`,
    {
      method:"POST",
      headers:{
        "Content-Type":"application/json",
        "X-Shopify-Access-Token":SHOPIFY_ADMIN_ACCESS_TOKEN
      },
      body:JSON.stringify({ query, variables })
    }
  );
  const json = await res.json();
  if (!res.ok || json.errors) throw new Error(JSON.stringify(json.errors));
  return json.data;
}

/* =========================
   CHECKOUT
========================= */
app.post("/checkout", async (req,res)=>{
  try{
    requireValidSignature(req);

    const { calculatorType, units, totalUnitsQty } = req.body;
    if (!units?.length) throw new Error("No units");

    const isSkylight = calculatorType === "skylight";
    const variantId = isSkylight
      ? ANCHOR_VARIANT_GID_SKYLIGHT
      : ANCHOR_VARIANT_GID_DGU;

    const lineItems = units.map(u=>({
      variantId,
      quantity: u.qty,
      priceOverride: money(u.unitPrice),
      customAttributes: isSkylight
        ? buildSkylightAttributes(u)
        : buildDguAttributes(u)
    }));

    const grandTotal = grandTotalFromUnits(units);

    const input = {
      note: "Created via RightGlaze calculator checkout",
      tags: [`calculator:${calculatorType}`],
      presentmentCurrencyCode: PRESENTMENT_CURRENCY_CODE,
      customAttributes: [
        { key:"Calculator Type", value:calculatorType },
        { key:"Total Units Qty", value:String(totalUnitsQty) },
        { key:"Grand Total", value:fmtGBP(grandTotal) }
      ],
      lineItems
    };

    const data = await shopifyGraphql(
      `mutation($input:DraftOrderInput!){
        draftOrderCreate(input:$input){
          draftOrder{ invoiceUrl }
          userErrors{ message }
        }
      }`,
      { input }
    );

    const out = data.draftOrderCreate;
    if (out.userErrors.length) throw new Error(out.userErrors[0].message);

    res.json({ invoiceUrl: out.draftOrder.invoiceUrl });

  }catch(e){
    console.error(e);
    res.status(500).json({ error:"Server error", reason:String(e.message||e) });
  }
});

/* =========================
   START
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=>console.log(`Server running on ${PORT}`));
