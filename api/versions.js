import { adminClient } from "./_lib/supabase.js";
import { allowCors, requireMethod, sendJson } from "./_lib/http.js";

export default async function handler(req, res) {
  if (allowCors(req, res)) return;
  if (!requireMethod(req, res, "GET")) return;

  const { data, error } = await adminClient
    .from("client_versions")
    .select("id, title, file_size, sha256, updated_at")
    .eq("is_enabled", true)
    .order("sort_order", { ascending: true })
    .order("title", { ascending: true });

  if (error) {
    sendJson(res, 500, { error: "database_error" });
    return;
  }

  sendJson(res, 200, { versions: data || [] });
}
