import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const publishableOrAnonKey =
  process.env.SUPABASE_PUBLISHABLE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY;
const serverSecretKey =
  process.env.SUPABASE_SECRET_KEY ||
  process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !publishableOrAnonKey || !serverSecretKey) {
  throw new Error("Missing Supabase environment variables");
}

export const authClient = createClient(supabaseUrl, publishableOrAnonKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

export const adminClient = createClient(supabaseUrl, serverSecretKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

export const storageBucket = process.env.SUPABASE_STORAGE_BUCKET || "clients";
export const signedUrlTtl = Number(process.env.SIGNED_URL_TTL || "120");

export async function findProfile(login) {
  const normalized = String(login || "").trim();
  if (!normalized) {
    return null;
  }

  const column = normalized.includes("@") ? "email" : "username";
  const { data, error } = await adminClient
    .from("profiles")
    .select("id, username, email, hwid_hash, is_active")
    .eq(column, normalized)
    .maybeSingle();

  if (error) {
    throw error;
  }
  return data;
}

export async function getUserByToken(accessToken) {
  const { data, error } = await authClient.auth.getUser(accessToken);
  if (error || !data?.user) {
    return null;
  }
  return data.user;
}

export async function profileForUser(userId) {
  const { data, error } = await adminClient
    .from("profiles")
    .select("id, username, email, hwid_hash, is_active")
    .eq("id", userId)
    .maybeSingle();

  if (error) {
    throw error;
  }
  return data;
}
