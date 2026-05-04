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

// 🌍 geolocalización con timeout
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

// 🤖 detección heurística mejorada
function isSuspicious(geo) {
  if (!geo || !geo.org) return true;

  const org = geo.org.toLowerCase();

  // flags directos
  if (geo.proxy === true) return true;
  if (geo.hosting === true) return true;

  // keywords
  const suspiciousKeywords = [
    "amazon", "google", "digitalocean", "ovh", "azure", "microsoft",
    "linode", "vultr", "hetzner", "cloudflare", "fastly", "akamai",
    "vpn", "proxy", "hosting", "server", "datacenter"
  ];

  return suspiciousKeywords.some(kw => org.includes(kw));
}

// 🧠 evaluación principal
app.get("/check", async (req, res) => {
  const ip = getIP(req);
  const geo = await getGeo(ip);

  const ua = req.headers["user-agent"] || "";
  const agent = useragent.parse(ua);

  const language = req.headers["accept-language"] || "";

  // 📍 checks
  const isSpain = geo.country === "ES";
  const isAndroid = agent.os.toString().toLowerCase().includes("android");
  const isSpanishLang = language.toLowerCase().includes("es");
  const vpn = isSuspicious(geo);

  // 🧮 scoring mejorado
  let score = 0;

  if (isSpain) score += 2;
  if (isAndroid) score += 2;
  if (isSpanishLang) score += 1;

  if (!isAndroid) score -= 10; // penalizar desktop

  if (vpn) score -= 10;
  else score += 2;

  // fallback si geo falla
  if (!geo.country) score -= 2;

  const allow = score >= 3;

  // 📊 LOG PARA TFG
  console.log("---- VISITA ----");
  console.log({
    ip,
    country: geo.country,
    org: geo.org,
    vpn,
    isAndroid,
    isSpanishLang,
    score,
    allow
  });

  res.json({
    allow,
    score
  });
});

// 🚀 rutas finales
app.get("/apk", (req, res) => {
  res.redirect("https://es.wikipedia.org/wiki/Bien_(filosof%C3%ADa)");
});

app.get("/home", (req, res) => {
  res.redirect("https://www.exteriores.gob.es/es/Paginas/Error-Cita.aspx");
});

// 🌐 root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// 🌐 puerto compatible con Render
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Servidor activo en puerto", PORT);
});