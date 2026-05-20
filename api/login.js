import {
  adminClient,
  getUserByToken,
  profileForUser,
  signedUrlTtl,
  storageBucket,
} from "./_lib/supabase.js";
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

  const accessToken = String(body.access_token || body.session_token || "").trim();
  const versionId = String(body.version_id || "").trim();
  const hwidHash = String(body.hwid_hash || "").trim();

  if (!accessToken || !versionId || !hwidHash) {
    sendJson(res, 400, { error: "missing_fields" });
    return;
  }

  try {
    const user = await getUserByToken(accessToken);
    if (!user) {
      sendJson(res, 403, { error: "bad_or_expired_token" });
      return;
    }

    const profile = await profileForUser(user.id);
    if (!profile || !profile.is_active) {
      sendJson(res, 403, { error: "bad_or_expired_token" });
      return;
    }

    if (profile.hwid_hash !== hwidHash) {
      sendJson(res, 403, { error: "hwid_mismatch" });
      return;
    }

    const { data: version, error: versionError } = await adminClient
      .from("client_versions")
      .select("id, title, storage_path, launch_args, sha256, file_size, updated_at, is_enabled")
      .eq("id", versionId)
      .maybeSingle();

    if (versionError) throw versionError;
    if (!version || !version.is_enabled) {
      sendJson(res, 400, { error: "version_unavailable" });
      return;
    }
    if (!version.storage_path || !version.sha256) {
      sendJson(res, 409, { error: "client_file_not_configured" });
      return;
    }

    const { data: signed, error: signedError } = await adminClient.storage
      .from(storageBucket)
      .createSignedUrl(version.storage_path, signedUrlTtl);

    if (signedError || !signed?.signedUrl) {
      sendJson(res, 409, { error: "client_file_not_configured" });
      return;
    }

    sendJson(res, 200, {
      ok: true,
      hwid_status: "ok",
      user: { username: profile.username },
      version: {
        id: version.id,
        title: version.title,
        sha256: version.sha256,
        file_size: version.file_size,
        launch_args: version.launch_args || "",
        updated_at: version.updated_at,
        download_url: signed.signedUrl,
      },
    });
  } catch (error) {
    console.error(error);
    sendJson(res, 500, { error: "server_error" });
  }
}
