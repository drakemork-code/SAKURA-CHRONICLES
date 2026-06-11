// ============================================================
// Sakura Chronicles — Auth Backend
// Express + Resend API (no usa SMTP, funciona en Railway Trial)
// Endpoints:
//   POST /send-code   → envía código 6 dígitos al email
//   POST /verify-code → verifica código, devuelve username e IP
// ============================================================

const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const https   = require("https");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ── Config Resend ─────────────────────────────────────────────
// En Railway: Variables → RESEND_API_KEY = re_xxxxxxxxxxxx
// Obtén tu key gratis en resend.com (no necesitas dominio propio)
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL     = "noreply@sakurachronicles.lat";

function sendEmail(to, subject, html) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ from: FROM_EMAIL, to, subject, html });
    const req = https.request(
      {
        hostname: "api.resend.com",
        path:     "/emails",
        method:   "POST",
        headers:  {
          "Authorization": "Bearer " + RESEND_API_KEY,
          "Content-Type":  "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300)
            resolve(JSON.parse(data));
          else
            reject(new Error("Resend " + res.statusCode + ": " + data));
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// ── Almacenamiento en memoria ─────────────────────────────────
const pendingCodes = new Map();
const usedEmails   = new Set();
const usedIPs      = new Set();
const DB_FILE = "./db.json";

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return;
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    (db.gmails || []).forEach((g) => usedEmails.add(g));
    (db.ips    || []).forEach((i) => usedIPs.add(i));
    console.log(`[DB] Cargado: ${usedEmails.size} emails, ${usedIPs.size} IPs`);
  } catch (e) {
    console.error("[DB] Error al cargar:", e.message);
  }
}

function saveDB() {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(
      { gmails: [...usedEmails], ips: [...usedIPs], updated: new Date().toISOString() },
      null,
      2
    )
  );
}

loadDB();

function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// ═════════════════════════════════════════════════════════════
// POST /send-code
// ═════════════════════════════════════════════════════════════
app.post("/send-code", async (req, res) => {
  const { gmail } = req.body || {};
  const ip = getClientIP(req);

  if (!gmail || !gmail.includes("@")) {
    return res.status(400).json({ ok: false, error: "Email inválido." });
  }
  if (usedEmails.has(gmail.toLowerCase())) {
    return res.status(400).json({ ok: false, error: "Este email ya tiene una cuenta." });
  }
  if (usedIPs.has(ip)) {
    return res.status(400).json({ ok: false, error: "Ya existe una cuenta desde esta IP." });
  }

  const existing = pendingCodes.get(gmail.toLowerCase());
  if (existing && Date.now() < existing.expires - 4 * 60 * 1000) {
    return res.status(429).json({ ok: false, error: "Espera 60 segundos antes de pedir otro código." });
  }

  const code    = generateCode();
  const expires = Date.now() + 5 * 60 * 1000;
  pendingCodes.set(gmail.toLowerCase(), { code, expires, ip });

  try {
    await sendEmail(
      gmail,
      "🌸 Tu código de verificación — Sakura Chronicles",
      `<div style="font-family:sans-serif;max-width:480px;margin:auto;background:#0a0a1a;color:#e8e0f0;padding:32px;border-radius:12px;border:1px solid #6644aa">
        <h2 style="color:#f0c040;text-align:center">✦ SAKURA CHRONICLES ✦</h2>
        <p style="text-align:center;color:#b0a0d0">Tu código de verificación es:</p>
        <div style="font-size:48px;font-weight:bold;letter-spacing:12px;text-align:center;color:#ffffff;background:#1a1230;padding:20px;border-radius:8px;margin:16px 0">
          ${code}
        </div>
        <p style="color:#806090;font-size:13px;text-align:center">
          Válido por <strong>5 minutos</strong>.<br>
          Si no creaste esta cuenta, ignora este email.
        </p>
      </div>`
    );
    console.log(`[Auth] Código enviado a ${gmail} desde IP ${ip}`);
    res.json({ ok: true });
  } catch (err) {
    console.error("[Auth] Error email:", err.message);
    res.status(500).json({ ok: false, error: "No se pudo enviar el email." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /verify-code
// ═════════════════════════════════════════════════════════════
app.post("/verify-code", (req, res) => {
  const { gmail, code } = req.body || {};
  const ip  = getClientIP(req);
  const key = (gmail || "").toLowerCase();

  const pending = pendingCodes.get(key);
  if (!pending)
    return res.status(400).json({ ok: false, error: "No hay código pendiente." });
  if (Date.now() > pending.expires) {
    pendingCodes.delete(key);
    return res.status(400).json({ ok: false, error: "Código expirado. Solicita uno nuevo." });
  }
  if (pending.code !== String(code).trim())
    return res.status(400).json({ ok: false, error: "Código incorrecto." });

  usedEmails.add(key);
  usedIPs.add(ip);
  pendingCodes.delete(key);
  saveDB();

  const username = key.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
  console.log(`[Auth] ✅ Cuenta verificada: ${key} | IP: ${ip} | username: ${username}`);
  res.json({ ok: true, username, ip, gmail: key });
});

// ── Health check ──────────────────────────────────────────────
app.get("/health", (_, res) =>
  res.json({ status: "ok", accounts: usedEmails.size, pending: pendingCodes.size })
);

app.listen(PORT, () => {
  console.log(`[Auth Server] Escuchando en puerto ${PORT}`);
  if (!RESEND_API_KEY) console.warn("[Auth] ⚠ RESEND_API_KEY no configurado");
});
