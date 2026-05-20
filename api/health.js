import { allowCors, requireMethod, sendJson } from "./_lib/http.js";

export default async function handler(req, res) {
  if (allowCors(req, res)) return;
  if (!requireMethod(req, res, "GET")) return;
  sendJson(res, 200, { ok: true });
}
