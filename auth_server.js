// ============================================================
// Sakura Chronicles — Auth Backend
// Express + Nodemailer (Gmail)
// Endpoints:
//   POST /send-code   → envía código 6 dígitos al Gmail
//   POST /verify-code → verifica código, devuelve username e IP
// ============================================================

const express    = require("express");
const nodemailer = require("nodemailer");
const crypto     = require("crypto");
const fs         = require("fs");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ── Config Gmail ──────────────────────────────────────────────
// En Railway: Settings → Variables → añadir estas dos
const GMAIL_USER = process.env.GMAIL_USER; // tucuenta@gmail.com
const GMAIL_PASS = process.env.GMAIL_PASS; // contraseña de aplicación (no la normal)

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,
  auth: { user: GMAIL_USER, pass: GMAIL_PASS },
  tls: { rejectUnauthorized: false },
});

// ── Almacenamiento en memoria (se resetea al reiniciar) ────────
// Para persistencia real → usar Railway's Postgres o un JSON file
const pendingCodes = new Map();  // gmail → { code, expires, ip }
const usedGmails   = new Set();  // gmails ya registrados (se carga de db.json)
const usedIPs      = new Set();  // IPs ya usadas

const DB_FILE = "./db.json";

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return;
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    (db.gmails || []).forEach(g => usedGmails.add(g));
    (db.ips    || []).forEach(i => usedIPs.add(i));
    console.log(`[DB] Cargado: ${usedGmails.size} gmails, ${usedIPs.size} IPs`);
  } catch (e) {
    console.error("[DB] Error al cargar:", e.message);
  }
}

function saveDB() {
  const db = {
    gmails: [...usedGmails],
    ips:    [...usedIPs],
    updated: new Date().toISOString(),
  };
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

loadDB();

// ── Helper: obtener IP real del cliente ───────────────────────
function getClientIP(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

// ── Helper: generar código ────────────────────────────────────
function generateCode() {
  return crypto.randomInt(100000, 999999).toString();
}

// ═════════════════════════════════════════════════════════════
// POST /send-code
// Body: { gmail: "user@gmail.com" }
// ═════════════════════════════════════════════════════════════
app.post("/send-code", async (req, res) => {
  const { gmail } = req.body || {};
  const ip = getClientIP(req);

  // Validaciones
  if (!gmail || !gmail.endsWith("@gmail.com")) {
    return res.status(400).json({ ok: false, error: "Gmail inválido." });
  }
  if (usedGmails.has(gmail.toLowerCase())) {
    return res.status(400).json({ ok: false, error: "Este Gmail ya tiene una cuenta." });
  }
  if (usedIPs.has(ip)) {
    return res.status(400).json({ ok: false, error: "Ya existe una cuenta registrada desde esta IP." });
  }

  // Rate limit simple: máx 1 código cada 60 segundos por gmail
  const existing = pendingCodes.get(gmail);
  if (existing && Date.now() < existing.expires - (5 * 60 * 1000 - 60 * 1000)) {
    return res.status(429).json({ ok: false, error: "Espera 60 segundos antes de pedir otro código." });
  }

  const code    = generateCode();
  const expires = Date.now() + 5 * 60 * 1000; // 5 minutos

  pendingCodes.set(gmail.toLowerCase(), { code, expires, ip });

  // Enviar email
  try {
    await transporter.sendMail({
      from:    `"Sakura Chronicles" <${GMAIL_USER}>`,
      to:      gmail,
      subject: "🌸 Tu código de verificación — Sakura Chronicles",
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:auto;background:#0a0a1a;color:#e8e0f0;padding:32px;border-radius:12px;border:1px solid #6644aa">
          <h2 style="color:#f0c040;text-align:center">✦ SAKURA CHRONICLES ✦</h2>
          <p style="text-align:center;color:#b0a0d0">Tu código de verificación es:</p>
          <div style="font-size:48px;font-weight:bold;letter-spacing:12px;text-align:center;color:#ffffff;background:#1a1230;padding:20px;border-radius:8px;margin:16px 0">
            ${code}
          </div>
          <p style="color:#806090;font-size:13px;text-align:center">
            Válido por <strong>5 minutos</strong>.<br>
            Si no creaste esta cuenta, ignora este email.
          </p>
        </div>
      `,
    });
    console.log(`[Auth] Código enviado a ${gmail} desde IP ${ip}`);
    // NOTA: en producción NO devolver el código. Aquí lo devolvemos
    // como fallback para testing sin email real configurado.
    res.json({ ok: true, code }); // ← quitar "code" en producción si quieres máxima seguridad
  } catch (err) {
    console.error("[Auth] Error email:", err.message);
    res.status(500).json({ ok: false, error: "No se pudo enviar el email. Verifica tu Gmail." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /verify-code
// Body: { gmail: "user@gmail.com", code: "123456" }
// ═════════════════════════════════════════════════════════════
app.post("/verify-code", (req, res) => {
  const { gmail, code } = req.body || {};
  const ip = getClientIP(req);
  const key = (gmail || "").toLowerCase();

  const pending = pendingCodes.get(key);
  if (!pending) {
    return res.status(400).json({ ok: false, error: "No hay código pendiente para ese Gmail." });
  }
  if (Date.now() > pending.expires) {
    pendingCodes.delete(key);
    return res.status(400).json({ ok: false, error: "Código expirado. Solicita uno nuevo." });
  }
  if (pending.code !== String(code).trim()) {
    return res.status(400).json({ ok: false, error: "Código incorrecto." });
  }

  // ✅ Verificado — registrar gmail e IP
  usedGmails.add(key);
  usedIPs.add(ip);
  pendingCodes.delete(key);
  saveDB();

  // Generar username base del gmail
  const username = key.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);

  console.log(`[Auth] ✅ Cuenta verificada: ${key} | IP: ${ip} | username base: ${username}`);
  res.json({ ok: true, username, ip, gmail: key });
});

// ── Health check (Railway lo usa para saber si el server está vivo)
app.get("/health", (_, res) => res.json({
  status: "ok",
  accounts: usedGmails.size,
  pending: pendingCodes.size,
}));

app.listen(PORT, () => {
  console.log(`[Auth Server] Escuchando en puerto ${PORT}`);
  if (!GMAIL_USER || !GMAIL_PASS) {
    console.warn("[Auth] ⚠ GMAIL_USER o GMAIL_PASS no configurados — los emails no se enviarán");
  }
});
