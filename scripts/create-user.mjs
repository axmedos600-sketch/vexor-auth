import crypto from "node:crypto";

const [loginArg, password, expiresAt = "2099-01-01"] = process.argv.slice(2);
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY");
}

if (!loginArg || !password) {
  throw new Error("Usage: node scripts/create-user.mjs <login> <password> [expiresAt]");
}

function hashPassword(raw) {
  const n = 16384;
  const r = 8;
  const p = 1;
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(raw, salt, 32, { N: n, r, p }).toString("hex");
  return `scrypt$${n}$${r}$${p}$${salt}$${hash}`;
}

const login = String(loginArg).trim().toLowerCase();
const response = await fetch(`${SUPABASE_URL}/rest/v1/launcher_users`, {
  method: "POST",
  headers: {
    apikey: SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
    "Content-Type": "application/json",
    Prefer: "return=representation"
  },
  body: JSON.stringify({
    login,
    password_hash: hashPassword(password),
    expires_at: new Date(expiresAt).toISOString()
  })
});

const body = await response.text();
if (!response.ok) {
  throw new Error(body);
}

console.log(`Created user: ${login}`);
