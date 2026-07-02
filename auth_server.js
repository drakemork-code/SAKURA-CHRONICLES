// ============================================================
// Sakura Chronicles — © 2024 Drake Andonov & Ruth Gonzaga Quimi
// Todos los derechos reservados. All rights reserved.
// Prohibida la copia, distribucion o modificacion no autorizada.
// Unauthorized copying, distribution or modification is prohibited.
// ============================================================
// Auth Backend — Express + Resend API + Firestore REST
// Endpoints:
//   GET  /version-check     → consulta de versión mínima / mantenimiento
//   POST /send-code        → envía código 6 dígitos al email
//   POST /verify-code      → verifica código, devuelve username e IP
//   POST /login            → login con email + password
//   POST /forgot-password  → envía link de reset de contraseña
//   POST /reset-password   → guarda nueva contraseña con token
//   POST /save-player      → guarda TODOS los datos del personaje (WoW-style)
//   POST /load-player      → carga TODOS los datos del personaje
// ============================================================

const express = require("express");
const crypto  = require("crypto");
const https   = require("https");
const fs      = require("fs");
const path    = require("path");

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "2mb" }));

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
    const sep    = path.includes("?") ? "&" : "?";
    const url    = `${FIRESTORE_BASE}/${path}${sep}key=${FIREBASE_API_KEY}`;
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

// ── Firestore value converters ─────────────────────────────────

function toFirestoreValue(v) {
  if (v === null || v === undefined) return { nullValue: null };
  if (typeof v === "string")  return { stringValue: v };
  if (typeof v === "boolean") return { booleanValue: v };
  if (typeof v === "number") {
    return Number.isInteger(v)
      ? { integerValue: String(v) }
      : { doubleValue: v };
  }
  if (Array.isArray(v)) {
    return { arrayValue: { values: v.map(toFirestoreValue) } };
  }
  if (typeof v === "object") {
    const fields = {};
    for (const [k, val] of Object.entries(v)) {
      fields[k] = toFirestoreValue(val);
    }
    return { mapValue: { fields } };
  }
  return { stringValue: String(v) };
}

function toFirestore(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    fields[k] = toFirestoreValue(v);
  }
  return { fields };
}

function fromFirestoreValue(v) {
  if (!v) return null;
  if ("stringValue"  in v) return v.stringValue;
  if ("booleanValue" in v) return v.booleanValue;
  if ("integerValue" in v) return Number(v.integerValue);
  if ("doubleValue"  in v) return v.doubleValue;
  if ("nullValue"    in v) return null;
  if ("arrayValue"   in v) {
    const vals = v.arrayValue?.values || [];
    return vals.map(fromFirestoreValue);
  }
  if ("mapValue" in v) {
    return fromFirestore(v.mapValue);
  }
  return null;
}

function fromFirestore(doc) {
  if (!doc || !doc.fields) return null;
  const obj = {};
  for (const [k, v] of Object.entries(doc.fields)) {
    obj[k] = fromFirestoreValue(v);
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
  const fields = Object.keys(data).map(k => `updateMask.fieldPaths=${encodeURIComponent(k)}`).join("&");
  await firestoreRequest(
    "PATCH",
    `${collection}/${encodeURIComponent(docId)}?${fields}`,
    body
  );
}

// ═════════════════════════════════════════════════════════════
// SISTEMA DE VERSIONES — control de versión mínima del cliente
//
// Fuente de verdad: documento Firestore "config/versions".
// Así, para bloquear una versión vieja, solo se edita ese
// documento (a mano en la consola de Firestore, o llamando
// POST /admin/versions con el ADMIN_TOKEN) — sin tocar código
// ni redeployar nada.
//
// Fallback: si Firestore falla (o al arrancar, antes de la
// primera lectura), se usa versions.json como semilla local.
// Cache en memoria de VERSION_CACHE_MS para no golpear Firestore
// en cada polling de cliente/servidor de combate.
// ═════════════════════════════════════════════════════════════
const VERSIONS_FILE     = path.join(__dirname, "versions.json");
const VERSION_CACHE_MS  = 30 * 1000;
const ADMIN_TOKEN       = process.env.ADMIN_TOKEN || "";

let _versionCache      = null; // { latest_version, minimum_version, download_url, maintenance, maintenance_message }
let _versionCacheAt    = 0;

function loadLocalVersionsFile() {
  try {
    const raw = fs.readFileSync(VERSIONS_FILE, "utf8");
    return JSON.parse(raw);
  } catch (e) {
    // Semilla mínima de emergencia si ni siquiera existe el archivo local
    return {
      latest_version:      "2.0.1",
      minimum_version:     "2.0.1",
      download_url:        "https://sakurachronicles.lat",
      maintenance:         false,
      maintenance_message: "",
    };
  }
}

function normalizeVersionDoc(doc) {
  const fallback = loadLocalVersionsFile();
  return {
    latest_version:      doc.latest_version      ?? fallback.latest_version,
    minimum_version:     doc.minimum_version     ?? fallback.minimum_version,
    download_url:        doc.download_url        ?? fallback.download_url,
    maintenance:         doc.maintenance         ?? false,
    maintenance_message: doc.maintenance_message ?? "",
  };
}

// Compara versiones semver-like "1.2.10" > "1.2.9" (numérico por segmento,
// no lexicográfico — así "1.2.10" no queda por debajo de "1.2.9").
function compareVersions(a, b) {
  const pa = String(a).split(".").map(n => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map(n => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const da = pa[i] || 0, db = pb[i] || 0;
    if (da !== db) return da > db ? 1 : -1;
  }
  return 0;
}

// Lee la config de versiones (Firestore, con cache + fallback local)
async function getVersionConfig(forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh && _versionCache && (now - _versionCacheAt) < VERSION_CACHE_MS) {
    return _versionCache;
  }
  try {
    const doc = await fsGet("config", "versions");
    if (doc) {
      _versionCache   = normalizeVersionDoc(doc);
      _versionCacheAt = now;
      return _versionCache;
    }
  } catch (e) {
    console.error("[Version] Error leyendo config/versions de Firestore:", e.message);
  }
  // Firestore no tiene el doc todavía, o falló: usar fallback local.
  // No se actualiza _versionCacheAt a "now" completo para reintentar pronto.
  if (_versionCache) return _versionCache; // último valor bueno conocido
  _versionCache   = normalizeVersionDoc(loadLocalVersionsFile());
  _versionCacheAt = now;
  return _versionCache;
}

// Escribe la config de versiones en Firestore y refresca la cache local
async function setVersionConfig(partial) {
  const current = await getVersionConfig(true);
  const merged  = normalizeVersionDoc({ ...current, ...partial });
  await fsSet("config", "versions", merged);
  _versionCache   = merged;
  _versionCacheAt = Date.now();
  return merged;
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
    await fsSet("users", key, {
      email:    key,
      username,
      password: password ? hashPassword(password) : "",
      ip,
      created:  new Date().toISOString(),
    });
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
// POST /save-player  — FULL SERVER-SIDE PERSISTENCE (WoW-style)
//
// Body esperado:
// {
//   gmail, password,
//   character_slot: 0|1|2,   ← índice del slot activo
//   character: {              ← datos de PlayerData
//     name, gender, race, hair_style,
//     skin_r, skin_g, skin_b,
//     hair_r, hair_g, hair_b,
//     eye_r,  eye_g,  eye_b,
//     outfit_r, outfit_g, outfit_b,
//     level, xp, max_hp, hp, max_energy, energy,
//     speed, base_attack, tutorial_done,
//     bronze, silver, gold,
//     gathering_skills: { mining:{level,xp}, woodcutting:{level,xp}, herbalism:{level,xp} },
//     crafting_skills:  { smithing:{level,xp}, tailoring:{level,xp}, alchemy:{level,xp} },
//   },
//   inventory: [              ← array de 40 slots (null o {key,qty,quality,durability})
//     null, { key:"iron_sword", qty:1, quality:"normal", durability:100 }, ...
//   ],
//   equipped: {               ← dict por slot
//     head: null, chest: {key,qty,quality,durability}, ...
//   },
//   bank: {
//     tier: 0,
//     items: [ null, {key,qty,quality,durability}, ... ]
//   }
// }
// ═════════════════════════════════════════════════════════════
app.post("/save-player", async (req, res) => {
  const { gmail, password, character_slot, character, inventory, equipped, bank } = req.body || {};
  const key = (gmail || "").toLowerCase();

  if (!key || !password)
    return res.status(400).json({ ok: false, error: "Email y contraseña requeridos." });

  try {
    const user = await fsGet("users", key);
    if (!user) return res.status(400).json({ ok: false, error: "Usuario no encontrado." });
    if (user.password !== hashPassword(password))
      return res.status(401).json({ ok: false, error: "Contraseña incorrecta." });

    const slot = typeof character_slot === "number" ? character_slot : 0;

    // Estructura del documento del jugador en Firestore
    // Usamos un solo doc "players/<email>" con campos anidados por slot
    const playerData = {
      updated: new Date().toISOString(),
      active_slot: slot,
      // Guardamos los tres slots por si existen — solo tocamos el slot activo
    };

    // Serializar datos del personaje (character)
    if (character) {
      playerData[`slot${slot}_character`] = JSON.stringify(character);
    }
    // Serializar inventario completo
    if (inventory !== undefined) {
      playerData[`slot${slot}_inventory`] = JSON.stringify(inventory);
    }
    // Serializar equipo equipado
    if (equipped !== undefined) {
      playerData[`slot${slot}_equipped`] = JSON.stringify(equipped);
    }
    // Serializar banco
    if (bank !== undefined) {
      playerData[`slot${slot}_bank`] = JSON.stringify(bank);
    }

    await fsSet("players", key, playerData);

    console.log(`[Game] ✅ Save completo: ${key} | slot:${slot} | lv:${character?.level ?? "?"} | bronze:${character?.bronze ?? "?"} | items:${Array.isArray(inventory) ? inventory.filter(Boolean).length : "?"}`);
    res.json({ ok: true });
  } catch (e) {
    console.error("[Firestore] Error save-player:", e.message);
    res.status(500).json({ ok: false, error: "Error guardando datos." });
  }
});

// ═════════════════════════════════════════════════════════════
// POST /load-player  — FULL SERVER-SIDE PERSISTENCE (WoW-style)
//
// Body: { gmail, password }
// Devuelve:
// {
//   ok: true,
//   active_slot: 0,
//   slots: [
//     {                        ← slot 0
//       character: {...},
//       inventory: [...],
//       equipped: {...},
//       bank: { tier, items:[...] }
//     },
//     null,                    ← slot 1 vacío
//     null,                    ← slot 2 vacío
//   ]
// }
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
      // Primera vez — slots vacíos
      return res.json({
        ok: true,
        active_slot: 0,
        slots: [null, null, null],
      });
    }

    // Reconstruir los 3 slots
    const slots = [0, 1, 2].map(slot => {
      const charStr = player[`slot${slot}_character`];
      if (!charStr) return null;

      let character = null, inventory = null, equipped = null, bank = null;
      try { character = JSON.parse(charStr); } catch (_) { character = null; }

      const invStr = player[`slot${slot}_inventory`];
      if (invStr) try { inventory = JSON.parse(invStr); } catch (_) { inventory = []; }

      const eqStr = player[`slot${slot}_equipped`];
      if (eqStr) try { equipped = JSON.parse(eqStr); } catch (_) { equipped = {}; }

      const bankStr = player[`slot${slot}_bank`];
      if (bankStr) try { bank = JSON.parse(bankStr); } catch (_) { bank = { tier: 0, items: [] }; }

      return { character, inventory, equipped, bank };
    });

    const active_slot = typeof player.active_slot === "number" ? player.active_slot : 0;

    console.log(`[Game] ✅ Load completo: ${key} | active_slot:${active_slot}`);
    res.json({ ok: true, active_slot, slots });
  } catch (e) {
    console.error("[Firestore] Error load-player:", e.message);
    res.status(500).json({ ok: false, error: "Error cargando datos." });
  }
});

// ═════════════════════════════════════════════════════════════
// GET/POST /version-check
//
// El cliente (y el servidor de combate) consultan este endpoint
// para saber si la versión que tienen puede seguir jugando.
//
// Body/Query esperado: { client_version: "1.0.14" }
// (GET usa query string ?client_version=1.0.14 — útil para
//  llamadas simples desde curl/health checks; POST usa JSON body,
//  que es lo que usa el cliente Godot)
//
// Respuesta:
// {
//   ok: true,
//   status: "OK" | "UPDATE_REQUIRED" | "MAINTENANCE",
//   client_version:  "1.0.14",
//   latest_version:  "1.0.15",
//   minimum_version: "1.0.15",
//   download_url:    "https://sakurachronicles.lat",
//   maintenance_message: ""
// }
// ═════════════════════════════════════════════════════════════
async function handleVersionCheck(req, res) {
  const clientVersion = String(
    (req.method === "GET" ? req.query.client_version : req.body?.client_version) || "0.0.0"
  ).trim();

  try {
    const cfg = await getVersionConfig();

    let status = "OK";
    if (cfg.maintenance) {
      status = "MAINTENANCE";
    } else if (compareVersions(clientVersion, cfg.minimum_version) < 0) {
      status = "UPDATE_REQUIRED";
    }

    res.json({
      ok: true,
      status,
      client_version:      clientVersion,
      latest_version:      cfg.latest_version,
      minimum_version:     cfg.minimum_version,
      download_url:        cfg.download_url,
      maintenance:          !!cfg.maintenance,
      maintenance_message: cfg.maintenance_message || "",
    });
  } catch (e) {
    console.error("[Version] Error en version-check:", e.message);
    // Fail-open en caso de error interno inesperado: no queremos tumbar
    // el juego entero por un bug en el propio chequeo de versión.
    res.json({
      ok: true,
      status: "OK",
      client_version: clientVersion,
      latest_version: clientVersion,
      minimum_version: "0.0.0",
      download_url: "https://sakurachronicles.lat",
      maintenance: false,
      maintenance_message: "",
    });
  }
}

app.get("/version-check", handleVersionCheck);
app.post("/version-check", handleVersionCheck);

// ═════════════════════════════════════════════════════════════
// POST /admin/versions  — actualizar versión mínima / mantenimiento
//
// Protegido con header "x-admin-token" que debe coincidir con la
// env var ADMIN_TOKEN configurada en Railway. Si ADMIN_TOKEN no
// está configurado, este endpoint se deshabilita por completo
// (fail-closed) para no dejarlo abierto por accidente.
//
// Body: cualquier subconjunto de
// { latest_version, minimum_version, download_url, maintenance, maintenance_message }
//
// Ejemplo para forzar actualización obligatoria a 1.0.16:
//   curl -X POST https://.../admin/versions \
//     -H "x-admin-token: TU_TOKEN" -H "Content-Type: application/json" \
//     -d '{"latest_version":"1.0.16","minimum_version":"1.0.16"}'
// ═════════════════════════════════════════════════════════════
app.post("/admin/versions", async (req, res) => {
  if (!ADMIN_TOKEN) {
    return res.status(503).json({ ok: false, error: "Admin endpoint deshabilitado (ADMIN_TOKEN no configurado)." });
  }
  const token = req.headers["x-admin-token"];
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ ok: false, error: "Token inválido." });
  }
  try {
    const merged = await setVersionConfig(req.body || {});
    console.log("[Version] Config actualizada por admin:", JSON.stringify(merged));
    res.json({ ok: true, config: merged });
  } catch (e) {
    console.error("[Version] Error guardando config:", e.message);
    res.status(500).json({ ok: false, error: "Error guardando configuración de versiones." });
  }
});

app.get("/admin/versions", async (req, res) => {
  if (!ADMIN_TOKEN) {
    return res.status(503).json({ ok: false, error: "Admin endpoint deshabilitado (ADMIN_TOKEN no configurado)." });
  }
  const token = req.headers["x-admin-token"];
  if (token !== ADMIN_TOKEN) {
    return res.status(401).json({ ok: false, error: "Token inválido." });
  }
  const cfg = await getVersionConfig(true);
  res.json({ ok: true, config: cfg });
});

// ── Health check ──────────────────────────────────────────────
app.get("/health", (_, res) =>
  res.json({ status: "ok", pending_codes: pendingCodes.size, reset_tokens: resetTokens.size })
);

app.listen(PORT, async () => {
  console.log(`[Auth Server] Escuchando en puerto ${PORT}`);
  if (!RESEND_API_KEY) console.warn("[Auth] ⚠ RESEND_API_KEY no configurado");
  if (!ADMIN_TOKEN) console.warn("[Auth] ⚠ ADMIN_TOKEN no configurado — /admin/versions deshabilitado");
  try {
    const cfg = await getVersionConfig(true);
    console.log(`[Version] Config activa: latest=${cfg.latest_version} minimum=${cfg.minimum_version} maintenance=${cfg.maintenance}`);
  } catch (e) {
    console.warn("[Version] No se pudo precargar config de versiones:", e.message);
  }
});
