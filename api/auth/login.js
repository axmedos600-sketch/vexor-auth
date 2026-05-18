const crypto = require("node:crypto");

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const JWT_SECRET = process.env.JWT_SECRET || "change-me";

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

function normalizeLogin(login) {
  return String(login || "").trim().toLowerCase();
}

function safeEqual(a, b) {
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function verifyPassword(password, stored) {
  const parts = String(stored || "").split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;

  const n = Number(parts[1]);
  const r = Number(parts[2]);
  const p = Number(parts[3]);
  const salt = parts[4];
  const expected = parts[5];
  const actual = crypto.scryptSync(String(password || ""), salt, expected.length / 2, { N: n, r, p }).toString("hex");
  return safeEqual(actual, expected);
}

function signToken(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(body).digest("base64url");
  return `${body}.${sig}`;
}

async function supabase(path, options = {}) {
  const response = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    ...options,
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      Prefer: "return=representation",
      ...(options.headers || {})
    }
  });

  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(data?.message || `supabase_${response.status}`);
  }
  return data;
}

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    return json(res, 405, { ok: false, message: "method_not_allowed" });
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    return json(res, 500, { ok: false, message: "server_is_not_configured" });
  }

  let body = req.body;
  if (!body || typeof body === "string") {
    try {
      body = JSON.parse(body || "{}");
    } catch {
      body = {};
    }
  }

  const login = normalizeLogin(body.login);
  const password = String(body.password || "");
  const hwid = String(body.hwid || "").trim();

  if (!login || !password || !hwid) {
    return json(res, 400, { ok: false, message: "Введите логин и пароль" });
  }

  try {
    const users = await supabase(
      `launcher_users?login=eq.${encodeURIComponent(login)}&select=id,login,password_hash,hwid,expires_at,is_banned&limit=1`
    );
    const user = Array.isArray(users) ? users[0] : null;

    if (!user || !verifyPassword(password, user.password_hash)) {
      return json(res, 401, { ok: false, message: "Неверный логин или пароль" });
    }

    if (user.is_banned) {
      return json(res, 403, { ok: false, message: "Аккаунт заблокирован" });
    }

    if (user.expires_at && new Date(user.expires_at).getTime() < Date.now()) {
      return json(res, 403, { ok: false, message: "Подписка закончилась" });
    }

    if (user.hwid && user.hwid !== hwid) {
      return json(res, 403, { ok: false, message: "HWID не совпадает" });
    }

    if (!user.hwid) {
      await supabase(`launcher_users?id=eq.${user.id}`, {
        method: "PATCH",
        body: JSON.stringify({ hwid })
      });
    }

    const token = signToken({
      sub: user.id,
      login: user.login,
      hwid,
      exp: Math.floor(Date.now() / 1000) + 3600
    });

    return json(res, 200, {
      ok: true,
      login: user.login,
      expiresAt: user.expires_at,
      token
    });
  } catch (error) {
    return json(res, 500, { ok: false, message: error.message || "auth_server_error" });
  }
};
