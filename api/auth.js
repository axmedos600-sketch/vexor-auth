import { adminClient, authClient, findProfile } from "./_lib/supabase.js";
import { allowCors, readBody, requireMethod, sendJson } from "./_lib/http.js";

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
  const password = String(body.password || "");
  const hwidHash = String(body.hwid_hash || "").trim();

  if (!username || !password || !hwidHash) {
    sendJson(res, 400, { error: "missing_fields" });
    return;
  }

  try {
    const profile = await findProfile(username);
    if (!profile || !profile.is_active) {
      sendJson(res, 401, { error: "bad_credentials" });
      return;
    }

    const { data: authData, error: authError } = await authClient.auth.signInWithPassword({
      email: profile.email,
      password,
    });

    if (authError || !authData?.session || authData.user.id !== profile.id) {
      sendJson(res, 401, { error: "bad_credentials" });
      return;
    }

    let hwidStatus = "ok";
    if (!profile.hwid_hash) {
      const { error } = await adminClient
        .from("profiles")
        .update({ hwid_hash: hwidHash, last_login_at: new Date().toISOString() })
        .eq("id", profile.id);
      if (error) throw error;
      hwidStatus = "bound";
    } else if (profile.hwid_hash !== hwidHash) {
      sendJson(res, 403, { error: "hwid_mismatch" });
      return;
    } else {
      await adminClient
        .from("profiles")
        .update({ last_login_at: new Date().toISOString() })
        .eq("id", profile.id);
    }

    sendJson(res, 200, {
      ok: true,
      access_token: authData.session.access_token,
      expires_at: authData.session.expires_at,
      hwid_status: hwidStatus,
      user: { username: profile.username },
    });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: "server_error" });
  }
}
