import { adminClient } from "./_lib/supabase.js";
import { allowCors, readBody, requireMethod, sendJson } from "./_lib/http.js";

function validUsername(username) {
  return /^[a-zA-Z0-9_]{3,24}$/.test(username);
}

export default async function handler(req, res) {
  if (allowCors(req, res)) return;
  if (!requireMethod(req, res, "POST")) return;

  let body;
  try {
    body = await readBody(req);
  } catch {
    sendJson(res, 400, { error: "bad_json" });
    return;
  }

  const username = String(body.username || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!username || !email || !password) {
    sendJson(res, 400, { error: "missing_fields" });
    return;
  }
  if (!validUsername(username)) {
    sendJson(res, 400, { error: "bad_username" });
    return;
  }
  if (password.length < 6) {
    sendJson(res, 400, { error: "weak_password" });
    return;
  }

  try {
    const { data: existingProfile, error: lookupError } = await adminClient
      .from("profiles")
      .select("id")
      .or(`username.eq.${username},email.eq.${email}`)
      .maybeSingle();

    if (lookupError) throw lookupError;
    if (existingProfile) {
      sendJson(res, 409, { error: "account_exists" });
      return;
    }

    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { username },
    });

    if (createError || !created?.user) {
      sendJson(res, 409, { error: "account_exists", message: createError?.message });
      return;
    }

    const { error: profileError } = await adminClient
      .from("profiles")
      .insert({
        id: created.user.id,
        username,
        email,
      });

    if (profileError) {
      await adminClient.auth.admin.deleteUser(created.user.id);
      throw profileError;
    }

    sendJson(res, 200, {
      ok: true,
      user: { username, email },
    });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: "server_error", message: error.message });
  }
}
