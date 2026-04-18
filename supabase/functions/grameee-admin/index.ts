import { createClient } from "npm:@supabase/supabase-js@2";
import bcrypt from "npm:bcryptjs";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serviceRoleKey = Deno.env.get("GRAMEEE_SERVICE_ROLE_KEY") ?? "";

const supabase = createClient(supabaseUrl, serviceRoleKey, {
  auth: {
    persistSession: false,
  },
});

function jsonResponse(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json",
    },
  });
}

function errorResponse(message: string, status = 400) {
  return jsonResponse({ error: message }, status);
}

function requireString(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

async function hashToken(token: string) {
  const bytes = new TextEncoder().encode(token);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function validateSession(token: string) {
  const tokenHash = await hashToken(token);

  const { data, error } = await supabase
    .from("grameee_admin_sessions")
    .select("id, username, expires_at")
    .eq("token_hash", tokenHash)
    .maybeSingle();

  if (error || !data) {
    return null;
  }

  if (new Date(data.expires_at).getTime() <= Date.now()) {
    await supabase.from("grameee_admin_sessions").delete().eq("id", data.id);
    return null;
  }

  await supabase
    .from("grameee_admin_sessions")
    .update({ last_used_at: new Date().toISOString() })
    .eq("id", data.id);

  return data;
}

async function handleLogin(password: string) {
  const { data, error } = await supabase
    .from("grameee_admin_accounts")
    .select("username, password_hash")
    .eq("username", "admin")
    .maybeSingle();

  if (error) {
    return errorResponse(`Admin account lookup failed: ${error.message}`, 500);
  }

  if (!data) {
    return errorResponse("Admin account does not exist yet.", 401);
  }

  if (!data.password_hash) {
    return errorResponse("Admin password has not been initialized yet.", 401);
  }

  const validPassword = await bcrypt.compare(password, data.password_hash);

  if (!validPassword) {
    return errorResponse("Invalid admin password.", 401);
  }

  const token = generateToken();
  const tokenHash = await hashToken(token);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  await supabase.from("grameee_admin_sessions").delete().eq("username", "admin");

  const { error: sessionError } = await supabase.from("grameee_admin_sessions").insert({
    username: "admin",
    token_hash: tokenHash,
    expires_at: expiresAt,
  });

  if (sessionError) {
    return errorResponse("Admin session could not be created.", 500);
  }

  return jsonResponse({
    token,
    username: "admin",
    expires_at: expiresAt,
  });
}

async function handleVerify(token: string) {
  const session = await validateSession(token);
  return jsonResponse({
    valid: Boolean(session),
    username: session?.username ?? null,
    expires_at: session?.expires_at ?? null,
  });
}

async function handleListPending(token: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { data, error } = await supabase
    .from("grameee_tools")
    .select("id, name, url, category, description, submitted_by_name, submitted_by_email, created_at")
    .eq("status", "pending")
    .order("created_at", { ascending: true });

  if (error) {
    return errorResponse("Pending submissions could not be loaded.", 500);
  }

  return jsonResponse({ items: data ?? [] });
}

async function handleListAll(token: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { data, error } = await supabase
    .from("grameee_tools")
    .select("id, name, url, category, description, status, created_at")
    .order("name", { ascending: true });

  if (error) {
    return errorResponse("All tools could not be loaded.", 500);
  }

  return jsonResponse({ items: data ?? [] });
}

async function handleListPendingProcessors(token: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { data, error } = await supabase
    .from("processors")
    .select("id, name, inputs, outputs, processing_time, description, status, submitted_by, created_at")
    .eq("status", "pending")
    .order("created_at", { ascending: true });

  if (error) {
    return errorResponse("Pending processor submissions could not be loaded.", 500);
  }

  return jsonResponse({ items: data ?? [] });
}

async function handleListAllProcessors(token: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { data, error } = await supabase
    .from("processors")
    .select("id, name, inputs, outputs, processing_time, description, status, submitted_by, approved_at, approved_by, created_at, updated_at")
    .order("name", { ascending: true });

  if (error) {
    return errorResponse("All processor records could not be loaded.", 500);
  }

  return jsonResponse({ items: data ?? [] });
}

async function handleApprove(token: string, toolId: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { error } = await supabase
    .from("grameee_tools")
    .update({
      status: "approved",
      approved_at: new Date().toISOString(),
      approved_by_email: session.username,
      updated_at: new Date().toISOString(),
    })
    .eq("id", toolId);

  if (error) {
    return errorResponse("Tool could not be approved.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleReject(token: string, toolId: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { error } = await supabase
    .from("grameee_tools")
    .delete()
    .eq("id", toolId);

  if (error) {
    return errorResponse("Tool could not be rejected.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleDeleteTool(token: string, toolId: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { error } = await supabase
    .from("grameee_tools")
    .delete()
    .eq("id", toolId);

  if (error) {
    return errorResponse("Tool could not be deleted.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleApproveProcessor(token: string, processorId: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { error } = await supabase
    .from("processors")
    .update({
      status: "approved",
      approved_at: new Date().toISOString(),
      approved_by: session.username,
      updated_at: new Date().toISOString(),
    })
    .eq("id", processorId);

  if (error) {
    return errorResponse(`Processor could not be approved: ${error.message}`, 500);
  }

  return jsonResponse({ ok: true });
}

async function handleRejectProcessor(token: string, processorId: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { error } = await supabase
    .from("processors")
    .delete()
    .eq("id", processorId)
    .eq("status", "pending");

  if (error) {
    return errorResponse(`Processor could not be rejected: ${error.message}`, 500);
  }

  return jsonResponse({ ok: true });
}

async function handleDeleteProcessor(token: string, processorId: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  const { error } = await supabase
    .from("processors")
    .delete()
    .eq("id", processorId);

  if (error) {
    return errorResponse(`Processor could not be deleted: ${error.message}`, 500);
  }

  return jsonResponse({ ok: true });
}

async function handleChangePassword(token: string, currentPassword: string, newPassword: string) {
  const session = await validateSession(token);

  if (!session) {
    return errorResponse("Invalid admin session.", 401);
  }

  if (newPassword.length < 10) {
    return errorResponse("New password must be at least 10 characters long.", 400);
  }

  const { data, error } = await supabase
    .from("grameee_admin_accounts")
    .select("password_hash")
    .eq("username", session.username)
    .maybeSingle();

  if (error || !data?.password_hash) {
    return errorResponse("Current admin password could not be verified.", 400);
  }

  const validPassword = await bcrypt.compare(currentPassword, data.password_hash);

  if (!validPassword) {
    return errorResponse("Current password is incorrect.", 401);
  }

  const nextHash = await bcrypt.hash(newPassword, 10);

  const { error: updateError } = await supabase
    .from("grameee_admin_accounts")
    .update({
      password_hash: nextHash,
      updated_at: new Date().toISOString(),
    })
    .eq("username", session.username);

  if (updateError) {
    return errorResponse("Admin password could not be updated.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleLogout(token: string) {
  const tokenHash = await hashToken(token);
  await supabase.from("grameee_admin_sessions").delete().eq("token_hash", tokenHash);
  return jsonResponse({ ok: true });
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") {
    return new Response("ok", {
      headers: corsHeaders,
    });
  }

  if (request.method !== "POST") {
    return errorResponse("Method not allowed.", 405);
  }

  if (!supabaseUrl || !serviceRoleKey) {
    return errorResponse("Function secrets are not configured.", 500);
  }

  let body: Record<string, unknown>;

  try {
    body = await request.json();
  } catch {
    return errorResponse("Invalid JSON body.", 400);
  }

  const action = requireString(body.action);
  const token = requireString(body.token);
  const password = requireString(body.password);
  const currentPassword = requireString(body.currentPassword);
  const newPassword = requireString(body.newPassword);
  const toolId = requireString(body.toolId);
  const processorId = requireString(body.processorId);

  switch (action) {
    case "login":
      return await handleLogin(password);
    case "verify":
      return await handleVerify(token);
    case "listPendingProcessors":
      return await handleListPendingProcessors(token);
    case "listAllProcessors":
      return await handleListAllProcessors(token);
    case "approveProcessor":
      return await handleApproveProcessor(token, processorId);
    case "rejectProcessor":
      return await handleRejectProcessor(token, processorId);
    case "deleteProcessor":
      return await handleDeleteProcessor(token, processorId);
    case "listPending":
      return await handleListPending(token);
    case "listAll":
      return await handleListAll(token);
    case "approve":
      return await handleApprove(token, toolId);
    case "reject":
      return await handleReject(token, toolId);
    case "deleteTool":
      return await handleDeleteTool(token, toolId);
    case "changePassword":
      return await handleChangePassword(token, currentPassword, newPassword);
    case "logout":
      return await handleLogout(token);
    default:
      return errorResponse("Unknown admin action.", 400);
  }
});
