// ============================================================
// Sakura Chronicles — © 2024 Drake Andonov & Ruth Gonzaga Quimi
// Todos los derechos reservados. All rights reserved.
// Prohibida la copia, distribucion o modificacion no autorizada.
// Unauthorized copying, distribution or modification is prohibited.
// ============================================================
// Auth Backend — Express + Resend API (funciona en Railway)
// Endpoints:
//   POST /send-code        → envía código 6 dígitos al email
//   POST /verify-code      → verifica código, devuelve username e IP
//   POST /forgot-password  → envía link de reset de contraseña
//   POST /reset-password   → guarda nueva contraseña con token
// ============================================================

const express = require("express");
const crypto  = require("crypto");
const fs      = require("fs");
const https   = require("https");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ── Config Resend ─────────────────────────────────────────────
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
const pendingCodes   = new Map(); // email → { code, expires, ip }
const resetTokens    = new Map(); // token → { email, expires }
const usedEmails     = new Set();
const usedIPs        = new Set();
const passwords      = new Map(); // email → hashedPassword
const DB_FILE = "./db.json";

function hashPassword(password) {
  return crypto.createHash("sha256").update(password + "sakura_salt_2024").digest("hex");
}

function loadDB() {
  if (!fs.existsSync(DB_FILE)) return;
  try {
    const db = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    (db.gmails    || []).forEach((g) => usedEmails.add(g));
    (db.ips       || []).forEach((i) => usedIPs.add(i));
    (db.passwords || []).forEach(([k, v]) => passwords.set(k, v));
    console.log(`[DB] Cargado: ${usedEmails.size} emails, ${usedIPs.size} IPs`);
  } catch (e) {
    console.error("[DB] Error al cargar:", e.message);
  }
}

function saveDB() {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(
      {
        gmails:    [...usedEmails],
        ips:       [...usedIPs],
        passwords: [...passwords.entries()],
        updated:   new Date().toISOString()
      },
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
  const { gmail, code, password } = req.body || {};
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

  // Guardar contraseña si se envía
  if (password) {
    passwords.set(key, hashPassword(password));
  }

  saveDB();

  const username = key.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
  console.log(`[Auth] ✅ Cuenta verificada: ${key} | IP: ${ip} | username: ${username}`);
  res.json({ ok: true, username, ip, gmail: key });
});

// ═════════════════════════════════════════════════════════════
// POST /forgot-password
// Body: { gmail }
// Envía un link de reset al correo del usuario
// ═════════════════════════════════════════════════════════════
app.post("/forgot-password", async (req, res) => {
  const { gmail } = req.body || {};
  const key = (gmail || "").toLowerCase();

  if (!key || !key.includes("@")) {
    return res.status(400).json({ ok: false, error: "Email inválido." });
  }

  // Siempre responder ok para no revelar si el email existe
  if (!usedEmails.has(key)) {
    return res.json({ ok: true, message: "Si el email existe, recibirás un enlace." });
  }

  // Generar token único
  const token   = crypto.randomBytes(32).toString("hex");
  const expires = Date.now() + 30 * 60 * 1000; // 30 minutos
  resetTokens.set(token, { email: key, expires });

  const SERVER_URL = process.env.SERVER_URL || "https://sakurachronicles.up.railway.app";
  const resetLink  = `${SERVER_URL}/reset-password?token=${token}`;

  try {
    await sendEmail(
      key,
      "🌸 Recuperar contraseña — Sakura Chronicles",
      `<div style="font-family:sans-serif;max-width:480px;margin:auto;background:#0a0a1a;color:#e8e0f0;padding:32px;border-radius:12px;border:1px solid #6644aa">
        <h2 style="color:#f0c040;text-align:center">✦ SAKURA CHRONICLES ✦</h2>
        <p style="text-align:center;color:#b0a0d0">Recibimos una solicitud para restablecer tu contraseña.</p>
        <div style="text-align:center;margin:24px 0">
          <a href="${resetLink}"
             style="background:#6644aa;color:#ffffff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px">
            Restablecer contraseña
          </a>
        </div>
        <p style="color:#806090;font-size:13px;text-align:center">
          Este enlace expira en <strong>30 minutos</strong>.<br>
          Si no solicitaste esto, ignora este email.
        </p>
      </div>`
    );
    console.log(`[Auth] Reset enviado a ${key}`);
    res.json({ ok: true, message: "Si el email existe, recibirás un enlace." });
  } catch (err) {
    console.error("[Auth] Error reset email:", err.message);
    res.status(500).json({ ok: false, error: "No se pudo enviar el email." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /reset-password
// Body: { token, newPassword }
// ═════════════════════════════════════════════════════════════
app.post("/reset-password", (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token || !newPassword) {
    return res.status(400).json({ ok: false, error: "Token y nueva contraseña requeridos." });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ ok: false, error: "La contraseña debe tener al menos 6 caracteres." });
  }

  const data = resetTokens.get(token);
  if (!data) {
    return res.status(400).json({ ok: false, error: "Token inválido o ya usado." });
  }
  if (Date.now() > data.expires) {
    resetTokens.delete(token);
    return res.status(400).json({ ok: false, error: "Token expirado. Solicita uno nuevo." });
  }

  passwords.set(data.email, hashPassword(newPassword));
  resetTokens.delete(token);
  saveDB();

  console.log(`[Auth] ✅ Contraseña restablecida para: ${data.email}`);
  res.json({ ok: true, message: "Contraseña actualizada correctamente." });
});

// ═════════════════════════════════════════════════════════════
// GET /reset-password?token=xxx
// Página web simple para ingresar nueva contraseña
// ═════════════════════════════════════════════════════════════
app.get("/reset-password", (req, res) => {
  const { token } = req.query;
  const data = resetTokens.get(token);

  if (!data || Date.now() > data.expires) {
    return res.send(`
      <html><body style="font-family:sans-serif;background:#0a0a1a;color:#e8e0f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
        <div style="text-align:center;padding:32px;background:#1a1230;border-radius:12px;border:1px solid #6644aa">
          <h2 style="color:#f0c040">✦ SAKURA CHRONICLES ✦</h2>
          <p style="color:#ff6060">❌ Este enlace es inválido o ha expirado.</p>
          <p style="color:#806090;font-size:13px">Solicita un nuevo enlace desde el juego.</p>
        </div>
      </body></html>
    `);
  }

  res.send(`
    <html><body style="font-family:sans-serif;background:#0a0a1a;color:#e8e0f0;display:flex;justify-content:center;align-items:center;height:100vh;margin:0">
      <div style="text-align:center;padding:32px;background:#1a1230;border-radius:12px;border:1px solid #6644aa;min-width:320px">
        <h2 style="color:#f0c040">✦ SAKURA CHRONICLES ✦</h2>
        <p style="color:#b0a0d0">Nueva contraseña para:<br><strong>${data.email}</strong></p>
        <input id="pw" type="password" placeholder="Nueva contraseña (mín. 6 caracteres)"
               style="width:100%;padding:12px;margin:12px 0;border-radius:8px;border:1px solid #6644aa;background:#0a0a1a;color:#fff;font-size:16px;box-sizing:border-box">
        <input id="pw2" type="password" placeholder="Confirmar contraseña"
               style="width:100%;padding:12px;margin:4px 0 16px;border-radius:8px;border:1px solid #6644aa;background:#0a0a1a;color:#fff;font-size:16px;box-sizing:border-box">
        <button onclick="doReset()"
                style="background:#6644aa;color:#fff;padding:14px 32px;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer;width:100%">
          Restablecer contraseña
        </button>
        <p id="msg" style="margin-top:12px;font-size:13px;color:#f0c040"></p>
      </div>
      <script>
        async function doReset() {
          const pw = document.getElementById('pw').value;
          const pw2 = document.getElementById('pw2').value;
          const msg = document.getElementById('msg');
          if (pw.length < 6) { msg.style.color='#ff6060'; msg.textContent='Mínimo 6 caracteres.'; return; }
          if (pw !== pw2) { msg.style.color='#ff6060'; msg.textContent='Las contraseñas no coinciden.'; return; }
          msg.style.color='#f0c040'; msg.textContent='Procesando...';
          const r = await fetch('/reset-password', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({ token: '${token}', newPassword: pw })
          });
          const d = await r.json();
          if (d.ok) {
            msg.style.color='#60ff90';
            msg.textContent='✅ Contraseña actualizada. Ya puedes iniciar sesión en el juego.';
            document.querySelector('button').disabled = true;
          } else {
            msg.style.color='#ff6060';
            msg.textContent='❌ ' + d.error;
          }
        }
      </script>
    </body></html>
  `);
});

// ── Health check ──────────────────────────────────────────────
app.get("/health", (_, res) =>
  res.json({ status: "ok", accounts: usedEmails.size, pending: pendingCodes.size })
);

app.listen(PORT, () => {
  console.log(`[Auth Server] Escuchando en puerto ${PORT}`);
  if (!RESEND_API_KEY) console.warn("[Auth] ⚠ RESEND_API_KEY no configurado");
});
