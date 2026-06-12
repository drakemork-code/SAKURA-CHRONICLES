// ============================================================
// Sakura Chronicles — © 2024 Drake Andonov & Ruth Gonzaga Quimi
// Todos los derechos reservados. All rights reserved.
// Prohibida la copia, distribucion o modificacion no autorizada.
// Unauthorized copying, distribution or modification is prohibited.
// ============================================================
// Auth Backend — Express + Resend API + Firestore REST
// Endpoints:
//   POST /send-code        → envía código 6 dígitos al email
//   POST /verify-code      → verifica código, devuelve username e IP
//   POST /login            → login con email + password
//   POST /forgot-password  → envía link de reset de contraseña
//   POST /reset-password   → guarda nueva contraseña con token
//   POST /save-player      → guarda datos del personaje en Firestore
//   GET  /load-player      → carga datos del personaje desde Firestore
// ============================================================

const express = require("express");
const crypto  = require("crypto");
const https   = require("https");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// ── Config Resend ─────────────────────────────────────────────
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const FROM_EMAIL     = "noreply@sakurachronicles.lat";

// ── Config Firestore REST ──────────────────────────────────────
const FIREBASE_API_KEY  = process.env.FIREBASE_API_KEY || "AIzaSyC41SQCDu9r7hGr9ZDYcdA_DybCmMVjYe0";
const FIRESTORE_PROJECT = "sakura-chronicles";
const FIRESTORE_BASE    = `https://firestore.googleapis.com/v1/projects/${FIRESTORE_PROJECT}/databases/(default)/documents`;

// ── Almacenamiento en memoria (temporal, para códigos y tokens) ─
const pendingCodes = new Map(); // email → { code, expires, ip }
const resetTokens  = new Map(); // token → { email, expires }

// ── Utilidades ─────────────────────────────────────────────────
function hashPassword(password) {
  return crypto.createHash("sha256").update(password + "sakura_salt_2024").digest("hex");
}

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

// ── Firestore helpers ──────────────────────────────────────────
function firestoreRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const url    = `${FIRESTORE_BASE}/${path}?key=${FIREBASE_API_KEY}`;
    const parsed = new URL(url);
    const data   = body ? JSON.stringify(body) : null;

    const options = {
      hostname: parsed.hostname,
      path:     parsed.pathname + parsed.search,
      method,
      headers: { "Content-Type": "application/json" },
    };
    if (data) options.headers["Content-Length"] = Buffer.byteLength(data);

    const req = https.request(options, (res) => {
      let raw = "";
      res.on("data", (c) => (raw += c));
      res.on("end", () => {
        try {
          const json = JSON.parse(raw);
          if (res.statusCode >= 400) reject(new Error(JSON.stringify(json)));
          else resolve(json);
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

// Convierte objeto JS → formato Firestore
function toFirestore(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === "string")  fields[k] = { stringValue: v };
    else if (typeof v === "number") fields[k] = { integerValue: v };
    else if (typeof v === "boolean") fields[k] = { booleanValue: v };
    else if (v === null) fields[k] = { nullValue: null };
  }
  return { fields };
}

// Convierte respuesta Firestore → objeto JS
function fromFirestore(doc) {
  if (!doc || !doc.fields) return null;
  const obj = {};
  for (const [k, v] of Object.entries(doc.fields)) {
    if (v.stringValue  !== undefined) obj[k] = v.stringValue;
    else if (v.integerValue !== undefined) obj[k] = Number(v.integerValue);
    else if (v.booleanValue !== undefined) obj[k] = v.booleanValue;
    else if (v.nullValue    !== undefined) obj[k] = null;
  }
  return obj;
}

// Lee un documento de Firestore
async function fsGet(collection, docId) {
  try {
    const doc = await firestoreRequest("GET", `${collection}/${encodeURIComponent(docId)}`);
    return fromFirestore(doc);
  } catch (e) {
    if (e.message.includes("NOT_FOUND") || e.message.includes("404")) return null;
    throw e;
  }
}

// Escribe/sobreescribe un documento de Firestore (PATCH = upsert)
async function fsSet(collection, docId, data) {
  const body = toFirestore(data);
  const fields = Object.keys(data).map(k => `updateMask.fieldPaths=${k}`).join("&");
  await firestoreRequest(
    "PATCH",
    `${collection}/${encodeURIComponent(docId)}?${fields}`,
    body
  );
}

// ── Email ──────────────────────────────────────────────────────
function sendEmail(to, subject, html) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ from: FROM_EMAIL, to, subject, html });
    const req = https.request(
      {
        hostname: "api.resend.com",
        path:     "/emails",
        method:   "POST",
        headers:  {
          "Authorization":  "Bearer " + RESEND_API_KEY,
          "Content-Type":   "application/json",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(JSON.parse(data));
          else reject(new Error("Resend " + res.statusCode + ": " + data));
        });
      }
    );
    req.on("error", reject);
    req.write(body);
    req.end();
  });
}

// ═════════════════════════════════════════════════════════════
// POST /send-code
// ═════════════════════════════════════════════════════════════
app.post("/send-code", async (req, res) => {
  const { gmail } = req.body || {};
  const ip  = getClientIP(req);
  const key = (gmail || "").toLowerCase();

  if (!key || !key.includes("@"))
    return res.status(400).json({ ok: false, error: "Email inválido." });

  // Verificar si ya existe en Firestore
  try {
    const existing = await fsGet("users", key);
    if (existing) return res.status(400).json({ ok: false, error: "Este email ya tiene una cuenta." });

    // Verificar IP
    const ipDoc = await fsGet("ips", ip.replace(/[.:]/g, "_"));
    if (ipDoc) return res.status(400).json({ ok: false, error: "Ya existe una cuenta desde esta IP." });
  } catch (e) {
    console.error("[Firestore] Error verificando usuario:", e.message);
    return res.status(500).json({ ok: false, error: "Error interno." });
  }

  const prev = pendingCodes.get(key);
  if (prev && Date.now() < prev.expires - 4 * 60 * 1000)
    return res.status(429).json({ ok: false, error: "Espera 60 segundos antes de pedir otro código." });

  const code    = generateCode();
  const expires = Date.now() + 5 * 60 * 1000;
  pendingCodes.set(key, { code, expires, ip });

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
    console.log(`[Auth] Código enviado a ${key} desde IP ${ip}`);
    res.json({ ok: true });
  } catch (err) {
    console.error("[Auth] Error email:", err.message);
    res.status(500).json({ ok: false, error: "No se pudo enviar el email." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /verify-code   (registro)
// ═════════════════════════════════════════════════════════════
app.post("/verify-code", async (req, res) => {
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

  pendingCodes.delete(key);

  const username = key.split("@")[0].replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 20);
  const ipKey    = ip.replace(/[.:]/g, "_");

  try {
    // Guardar usuario en Firestore
    await fsSet("users", key, {
      email:    key,
      username,
      password: password ? hashPassword(password) : "",
      ip,
      created:  new Date().toISOString(),
    });
    // Guardar IP en Firestore
    await fsSet("ips", ipKey, { email: key, created: new Date().toISOString() });

    console.log(`[Auth] ✅ Cuenta creada: ${key} | IP: ${ip} | username: ${username}`);
    res.json({ ok: true, username, ip, gmail: key });
  } catch (e) {
    console.error("[Firestore] Error guardando usuario:", e.message);
    res.status(500).json({ ok: false, error: "Error guardando cuenta." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /login
// ═════════════════════════════════════════════════════════════
app.post("/login", async (req, res) => {
  const { gmail, password } = req.body || {};
  const key = (gmail || "").toLowerCase();

  if (!key || !password)
    return res.status(400).json({ ok: false, error: "Email y contraseña requeridos." });

  try {
    const user = await fsGet("users", key);
    if (!user)
      return res.status(400).json({ ok: false, error: "Email no registrado." });
    if (user.password !== hashPassword(password))
      return res.status(400).json({ ok: false, error: "Contraseña incorrecta." });

    console.log(`[Auth] ✅ Login: ${key}`);
    res.json({ ok: true, username: user.username, gmail: key });
  } catch (e) {
    console.error("[Firestore] Error en login:", e.message);
    res.status(500).json({ ok: false, error: "Error interno." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /forgot-password
// ═════════════════════════════════════════════════════════════
app.post("/forgot-password", async (req, res) => {
  const { gmail } = req.body || {};
  const key = (gmail || "").toLowerCase();

  if (!key || !key.includes("@"))
    return res.status(400).json({ ok: false, error: "Email inválido." });

  try {
    const user = await fsGet("users", key);
    if (!user) return res.json({ ok: true, message: "Si el email existe, recibirás un enlace." });

    const token   = crypto.randomBytes(32).toString("hex");
    const expires = Date.now() + 30 * 60 * 1000;
    resetTokens.set(token, { email: key, expires });

    const SERVER_URL = process.env.SERVER_URL || "https://sakurachronicles.up.railway.app";
    const resetLink  = `${SERVER_URL}/reset-password?token=${token}`;

    await sendEmail(
      key,
      "🌸 Recuperar contraseña — Sakura Chronicles",
      `<div style="font-family:sans-serif;max-width:480px;margin:auto;background:#0a0a1a;color:#e8e0f0;padding:32px;border-radius:12px;border:1px solid #6644aa">
        <h2 style="color:#f0c040;text-align:center">✦ SAKURA CHRONICLES ✦</h2>
        <p style="text-align:center;color:#b0a0d0">Recibimos una solicitud para restablecer tu contraseña.</p>
        <div style="text-align:center;margin:24px 0">
          <a href="${resetLink}" style="background:#6644aa;color:#ffffff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:16px">
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
    console.error("[Auth] Error reset:", err.message);
    res.status(500).json({ ok: false, error: "No se pudo enviar el email." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /reset-password  (API)
// ═════════════════════════════════════════════════════════════
app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body || {};

  if (!token || !newPassword)
    return res.status(400).json({ ok: false, error: "Token y nueva contraseña requeridos." });
  if (newPassword.length < 6)
    return res.status(400).json({ ok: false, error: "La contraseña debe tener al menos 6 caracteres." });

  const data = resetTokens.get(token);
  if (!data) return res.status(400).json({ ok: false, error: "Token inválido o ya usado." });
  if (Date.now() > data.expires) {
    resetTokens.delete(token);
    return res.status(400).json({ ok: false, error: "Token expirado. Solicita uno nuevo." });
  }

  try {
    await fsSet("users", data.email, { password: hashPassword(newPassword) });
    resetTokens.delete(token);
    console.log(`[Auth] ✅ Contraseña restablecida para: ${data.email}`);
    res.json({ ok: true, message: "Contraseña actualizada correctamente." });
  } catch (e) {
    console.error("[Firestore] Error reset password:", e.message);
    res.status(500).json({ ok: false, error: "Error guardando contraseña." });
  }
});

// ═════════════════════════════════════════════════════════════
// GET /reset-password?token=xxx  (página web)
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
          const pw  = document.getElementById('pw').value;
          const pw2 = document.getElementById('pw2').value;
          const msg = document.getElementById('msg');
          if (pw.length < 6) { msg.style.color='#ff6060'; msg.textContent='Mínimo 6 caracteres.'; return; }
          if (pw !== pw2)    { msg.style.color='#ff6060'; msg.textContent='Las contraseñas no coinciden.'; return; }
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

// ═════════════════════════════════════════════════════════════
// POST /save-player
// Body: { gmail, password, coins, xp, level, slot1, slot2, slot3 }
// ═════════════════════════════════════════════════════════════
app.post("/save-player", async (req, res) => {
  const { gmail, password, coins, xp, level, slot1, slot2, slot3 } = req.body || {};
  const key = (gmail || "").toLowerCase();

  if (!key || !password)
    return res.status(400).json({ ok: false, error: "Email y contraseña requeridos." });

  try {
    const user = await fsGet("users", key);
    if (!user) return res.status(400).json({ ok: false, error: "Usuario no encontrado." });
    if (user.password !== hashPassword(password))
      return res.status(401).json({ ok: false, error: "Contraseña incorrecta." });

    await fsSet("players", key, {
      coins:   coins  ?? 0,
      xp:      xp     ?? 0,
      level:   level  ?? 1,
      slot1:   slot1  ?? "",
      slot2:   slot2  ?? "",
      slot3:   slot3  ?? "",
      updated: new Date().toISOString(),
    });

    console.log(`[Game] ✅ Guardado: ${key} | coins:${coins} xp:${xp} lv:${level}`);
    res.json({ ok: true });
  } catch (e) {
    console.error("[Firestore] Error save-player:", e.message);
    res.status(500).json({ ok: false, error: "Error guardando datos." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /load-player
// Body: { gmail, password }
// ═════════════════════════════════════════════════════════════
app.post("/load-player", async (req, res) => {
  const { gmail, password } = req.body || {};
  const key = (gmail || "").toLowerCase();

  if (!key || !password)
    return res.status(400).json({ ok: false, error: "Email y contraseña requeridos." });

  try {
    const user = await fsGet("users", key);
    if (!user) return res.status(400).json({ ok: false, error: "Usuario no encontrado." });
    if (user.password !== hashPassword(password))
      return res.status(401).json({ ok: false, error: "Contraseña incorrecta." });

    const player = await fsGet("players", key);
    if (!player) {
      // Primera vez — devolver datos por defecto
      return res.json({ ok: true, coins: 0, xp: 0, level: 1, slot1: "", slot2: "", slot3: "" });
    }

    console.log(`[Game] ✅ Cargado: ${key}`);
    res.json({ ok: true, ...player });
  } catch (e) {
    console.error("[Firestore] Error load-player:", e.message);
    res.status(500).json({ ok: false, error: "Error cargando datos." });
  }
});

// ── Health check ──────────────────────────────────────────────
app.get("/health", (_, res) =>
  res.json({ status: "ok", pending_codes: pendingCodes.size, reset_tokens: resetTokens.size })
);

app.listen(PORT, () => {
  console.log(`[Auth Server] Escuchando en puerto ${PORT}`);
  if (!RESEND_API_KEY) console.warn("[Auth] ⚠ RESEND_API_KEY no configurado");
});
