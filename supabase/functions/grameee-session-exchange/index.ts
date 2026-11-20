import { createClient } from "npm:@supabase/supabase-js@2.119.1";
import {
  isExactRedirectAllowed,
  isExchangeToken,
  isPkceVerifier,
  issueMaterial,
  keyedHash,
  normalizeClientId,
  normalizePrivileges,
  normalizeRole,
  sessionMaterial,
  sha256Base64Url,
  verifyClientSecret,
} from "./exchange.mjs";

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serviceRoleKey = Deno.env.get("GRAMEEE_SERVICE_ROLE_KEY") ?? "";
const exchangeHmacSecret = Deno.env.get("GRAMEEE_SESSION_EXCHANGE_HMAC_SECRET") ?? "";
const enabledFlag = "session_exchange_enabled";
const maxBodyBytes = 16_384;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const supabase = createClient(supabaseUrl, serviceRoleKey, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const responseHeaders = {
  "Cache-Control": "no-store, max-age=0",
  "Pragma": "no-cache",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Content-Type": "application/json; charset=utf-8",
};

type ExchangeClient = {
  client_id: string;
  audience: string;
  redirect_uris: string[];
  client_secret_hash: string;
  enabled: boolean;
};

type ExchangeCode = {
  exchange_id: string;
  code_hash: string;
  user_id: string;
  source_session_id: string;
  client_id: string;
  audience: string;
  redirect_uri: string;
  pkce_challenge: string;
  issued_at: string;
  expires_at: string;
  consumed_at: string | null;
  redeem_attempt_count: number;
};

type ApplicationSession = {
  application_session_id: string;
  user_id: string;
  source_session_id: string;
  client_id: string;
  audience: string;
  trusted_role: string;
  trusted_privileges: Record<string, boolean>;
  issued_at: string;
  last_seen_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  revoked_at: string | null;
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: responseHeaders });
}

function genericDenial(status = 401) {
  return json({ error: "Session exchange request was denied." }, status);
}

function requireString(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function requestContextSource(request: Request) {
  const forwarded = requireString(request.headers.get("x-forwarded-for")).split(",")[0].slice(0, 128);
  const userAgent = requireString(request.headers.get("user-agent")).slice(0, 256);
  return `${forwarded || "unknown"}\u0000${userAgent || "unknown"}`;
}

async function requestContextHash(request: Request) {
  return await keyedHash(exchangeHmacSecret, "request-context", [requestContextSource(request)]);
}

async function isEnabled() {
  const { data, error } = await supabase
    .from("grameee_security_flags")
    .select("enabled")
    .eq("flag_key", enabledFlag)
    .maybeSingle();
  if (error) {
    console.error("Session exchange containment lookup failed.");
    return false;
  }
  return data?.enabled === true;
}

async function getClient(clientIdInput: unknown) {
  const clientId = normalizeClientId(clientIdInput);
  if (!clientId) return null;
  const { data, error } = await supabase
    .from("grameee_session_exchange_clients")
    .select("client_id, audience, redirect_uris, client_secret_hash, enabled")
    .eq("client_id", clientId)
    .maybeSingle();
  if (error) throw new Error("Client lookup failed.");
  return data ? data as ExchangeClient : null;
}

async function authenticateClient(request: Request, clientIdInput: unknown) {
  const client = await getClient(clientIdInput);
  const suppliedSecret = requireString(request.headers.get("x-grameee-client-secret"));
  const valid = client?.enabled === true && await verifyClientSecret(
    exchangeHmacSecret,
    client?.client_id || "invalid",
    suppliedSecret,
    client?.client_secret_hash || "0".repeat(64),
  );
  return valid ? client : null;
}

function decodeJwtSessionId(token: string) {
  try {
    const payloadPart = token.split(".")[1] || "";
    const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(payloadPart.length / 4) * 4, "=");
    const payload = JSON.parse(atob(padded));
    const sessionId = requireString(payload?.session_id);
    return uuidPattern.test(sessionId) ? sessionId : "";
  } catch {
    return "";
  }
}

async function isSourceSessionActive(sessionId: string, userId: string) {
  if (!uuidPattern.test(sessionId) || !uuidPattern.test(userId)) return false;
  const { data, error } = await supabase.rpc("grameee_is_active_session", {
    p_session_id: sessionId,
    p_user_id: userId,
  });
  return !error && data === true;
}

async function getLivePrincipal(userId: string) {
  const { data, error } = await supabase.auth.admin.getUserById(userId);
  const user = data?.user;
  if (error || !user || user.deleted_at || user.app_metadata?.grameee_removed === true) return null;
  const role = normalizeRole(user.app_metadata?.grameee_role);
  return {
    userId: user.id,
    role,
    privileges: normalizePrivileges(user.app_metadata?.grameee_privileges, role),
  };
}

async function writeAudit(event: Record<string, unknown>) {
  const { error } = await supabase.from("grameee_session_exchange_events").insert(event);
  if (error) console.error("Session exchange audit write failed.");
  return !error;
}

async function recordDenial(request: Request, values: Record<string, unknown>) {
  await writeAudit({
    event_type: values.event_type || "redeem",
    outcome: values.outcome || "denied",
    exchange_id: values.exchange_id || null,
    application_session_id: values.application_session_id || null,
    user_id: values.user_id || null,
    client_id: values.client_id || null,
    audience: values.audience || null,
    reason: values.reason || "request_denied",
    request_context_hash: await requestContextHash(request),
  });
}

async function handleIssue(request: Request, body: Record<string, unknown>) {
  const client = await getClient(body.clientId);
  const redirectUri = requireString(body.redirectUri);
  const pkceChallenge = requireString(body.pkceChallenge);
  if (!client?.enabled || !isExactRedirectAllowed(redirectUri, client.redirect_uris) || !/^[A-Za-z0-9_-]{43}$/.test(pkceChallenge)) {
    await recordDenial(request, { event_type: "issue", client_id: client?.client_id, audience: client?.audience, reason: "client_binding_invalid" });
    return genericDenial();
  }

  const authorization = requireString(request.headers.get("authorization"));
  const token = authorization.replace(/^Bearer\s+/i, "");
  if (!token || token === authorization) return genericDenial();
  const { data, error } = await supabase.auth.getUser(token);
  const user = data?.user;
  const sessionId = decodeJwtSessionId(token);
  if (error || !user || user.app_metadata?.grameee_removed === true || !await isSourceSessionActive(sessionId, user.id)) {
    await recordDenial(request, { event_type: "issue", client_id: client.client_id, audience: client.audience, reason: "source_session_invalid" });
    return genericDenial();
  }

  const { count, error: countError } = await supabase
    .from("grameee_session_exchange_codes")
    .select("exchange_id", { count: "exact", head: true })
    .eq("user_id", user.id)
    .eq("client_id", client.client_id)
    .is("consumed_at", null)
    .gt("expires_at", new Date().toISOString());
  if (countError) return json({ error: "Session exchange is temporarily unavailable." }, 503);
  if ((count || 0) >= 5) {
    await recordDenial(request, { event_type: "issue", user_id: user.id, client_id: client.client_id, audience: client.audience, reason: "outstanding_limit" });
    return genericDenial(429);
  }

  const material = await issueMaterial({
    secret: exchangeHmacSecret,
    userId: user.id,
    sessionId,
    clientId: client.client_id,
    audience: client.audience,
    redirectUri,
    pkceChallenge,
    contextSource: requestContextSource(request),
  });
  const { data: inserted, error: insertError } = await supabase
    .from("grameee_session_exchange_codes")
    .insert(material.row)
    .select("exchange_id")
    .single();
  if (insertError || !inserted) return json({ error: "Session exchange is temporarily unavailable." }, 503);

  const audited = await writeAudit({
    event_type: "issue",
    outcome: "success",
    exchange_id: inserted.exchange_id,
    user_id: user.id,
    client_id: client.client_id,
    audience: client.audience,
    request_context_hash: material.row.issue_context_hash,
  });
  if (!audited) {
    await supabase.from("grameee_session_exchange_codes").delete().eq("exchange_id", inserted.exchange_id);
    return json({ error: "Session exchange is temporarily unavailable." }, 503);
  }
  return json({ code: material.code, expiresIn: 60, tokenType: "exchange_code" }, 201);
}

async function markCodeFailure(code: ExchangeCode, reason: string, contextHash: string) {
  await supabase
    .from("grameee_session_exchange_codes")
    .update({
      redeem_attempt_count: Math.min(code.redeem_attempt_count + 1, 5),
      last_failure_reason: reason,
      redeem_context_hash: contextHash,
    })
    .eq("exchange_id", code.exchange_id)
    .eq("redeem_attempt_count", code.redeem_attempt_count)
    .is("consumed_at", null);
}

async function handleRedeem(request: Request, body: Record<string, unknown>) {
  const client = await authenticateClient(request, body.clientId);
  if (!client) return genericDenial();
  const rawCode = requireString(body.code);
  const redirectUri = requireString(body.redirectUri);
  const verifier = requireString(body.codeVerifier);
  if (!isExchangeToken(rawCode) || !isPkceVerifier(verifier)) {
    await recordDenial(request, { event_type: "redeem", client_id: client.client_id, audience: client.audience, reason: "request_format_invalid" });
    return genericDenial();
  }

  const codeHash = await keyedHash(exchangeHmacSecret, "exchange-code", [rawCode]);
  const contextHash = await requestContextHash(request);
  const { data, error } = await supabase
    .from("grameee_session_exchange_codes")
    .select("exchange_id, code_hash, user_id, source_session_id, client_id, audience, redirect_uri, pkce_challenge, issued_at, expires_at, consumed_at, redeem_attempt_count")
    .eq("code_hash", codeHash)
    .maybeSingle();
  if (error || !data) {
    await recordDenial(request, { event_type: "redeem", client_id: client.client_id, audience: client.audience, reason: "code_unknown" });
    return genericDenial();
  }
  const code = data as ExchangeCode;
  if (code.consumed_at) {
    await recordDenial(request, { event_type: "redeem", outcome: "replay", exchange_id: code.exchange_id, user_id: code.user_id, client_id: client.client_id, audience: client.audience, reason: "code_replayed" });
    return genericDenial();
  }
  if (Date.parse(code.expires_at) <= Date.now()) {
    await markCodeFailure(code, "expired", contextHash);
    await recordDenial(request, { event_type: "redeem", outcome: "expired", exchange_id: code.exchange_id, user_id: code.user_id, client_id: client.client_id, audience: client.audience, reason: "code_expired" });
    return genericDenial();
  }
  const derivedChallenge = await sha256Base64Url(verifier);
  const bindingsValid = code.client_id === client.client_id
    && code.audience === client.audience
    && code.redirect_uri === redirectUri
    && isExactRedirectAllowed(redirectUri, client.redirect_uris)
    && code.pkce_challenge === derivedChallenge
    && code.redeem_attempt_count < 5;
  if (!bindingsValid) {
    await markCodeFailure(code, "binding_mismatch", contextHash);
    await recordDenial(request, { event_type: "redeem", exchange_id: code.exchange_id, user_id: code.user_id, client_id: client.client_id, audience: client.audience, reason: "binding_mismatch" });
    return genericDenial();
  }
  if (!await isSourceSessionActive(code.source_session_id, code.user_id)) {
    await markCodeFailure(code, "source_session_inactive", contextHash);
    await recordDenial(request, { event_type: "redeem", exchange_id: code.exchange_id, user_id: code.user_id, client_id: client.client_id, audience: client.audience, reason: "source_session_inactive" });
    return genericDenial();
  }
  const principal = await getLivePrincipal(code.user_id);
  if (!principal) return genericDenial();

  const consumedAt = new Date().toISOString();
  const { data: consumed, error: consumeError } = await supabase
    .from("grameee_session_exchange_codes")
    .update({ consumed_at: consumedAt, redeem_context_hash: contextHash, last_failure_reason: null })
    .eq("exchange_id", code.exchange_id)
    .eq("redeem_attempt_count", code.redeem_attempt_count)
    .is("consumed_at", null)
    .gt("expires_at", consumedAt)
    .select("exchange_id")
    .maybeSingle();
  if (consumeError || !consumed) {
    await recordDenial(request, { event_type: "redeem", outcome: "replay", exchange_id: code.exchange_id, user_id: code.user_id, client_id: client.client_id, audience: client.audience, reason: "consume_race" });
    return genericDenial();
  }

  const session = await sessionMaterial({ secret: exchangeHmacSecret, role: principal.role });
  const { data: created, error: sessionError } = await supabase
    .from("grameee_application_sessions")
    .insert({
      session_token_hash: session.sessionTokenHash,
      user_id: code.user_id,
      source_session_id: code.source_session_id,
      client_id: client.client_id,
      audience: client.audience,
      trusted_role: principal.role,
      trusted_privileges: principal.privileges,
      idle_expires_at: session.idleExpiresAt,
      absolute_expires_at: session.absoluteExpiresAt,
    })
    .select("application_session_id")
    .single();
  if (sessionError || !created) {
    await supabase.from("grameee_session_exchange_codes").update({ last_failure_reason: "session_create_failed" }).eq("exchange_id", code.exchange_id);
    await recordDenial(request, { event_type: "redeem", exchange_id: code.exchange_id, user_id: code.user_id, client_id: client.client_id, audience: client.audience, reason: "session_create_failed" });
    return json({ error: "Session exchange is temporarily unavailable." }, 503);
  }

  const audited = await writeAudit({
    event_type: "redeem",
    outcome: "success",
    exchange_id: code.exchange_id,
    application_session_id: created.application_session_id,
    user_id: code.user_id,
    client_id: client.client_id,
    audience: client.audience,
    request_context_hash: contextHash,
  });
  if (!audited) {
    await supabase.from("grameee_application_sessions").update({ revoked_at: new Date().toISOString(), revocation_reason: "security_response" }).eq("application_session_id", created.application_session_id);
    return json({ error: "Session exchange is temporarily unavailable." }, 503);
  }

  return json({
    sessionToken: session.sessionToken,
    session: {
      audience: client.audience,
      idleExpiresAt: session.idleExpiresAt,
      absoluteExpiresAt: session.absoluteExpiresAt,
    },
    principal,
  });
}

async function revokeStoredSession(session: ApplicationSession, reason: string) {
  await supabase
    .from("grameee_application_sessions")
    .update({ revoked_at: new Date().toISOString(), revocation_reason: reason })
    .eq("application_session_id", session.application_session_id)
    .is("revoked_at", null);
}

function privilegesMatch(left: Record<string, boolean>, right: Record<string, boolean>) {
  const keys = ["ecosystem", "askGre", "offerSolutions", "askHelp", "needsMap", "gre"];
  return keys.every((key) => (left?.[key] === true) === (right?.[key] === true));
}

async function findApplicationSession(client: ExchangeClient, token: string) {
  if (!isExchangeToken(token)) return null;
  const tokenHash = await keyedHash(exchangeHmacSecret, "application-session", [token]);
  const { data, error } = await supabase
    .from("grameee_application_sessions")
    .select("application_session_id, user_id, source_session_id, client_id, audience, trusted_role, trusted_privileges, issued_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at")
    .eq("session_token_hash", tokenHash)
    .eq("client_id", client.client_id)
    .maybeSingle();
  if (error) throw new Error("Application session lookup failed.");
  return data ? data as ApplicationSession : null;
}

async function handleValidate(request: Request, body: Record<string, unknown>) {
  const client = await authenticateClient(request, body.clientId);
  if (!client) return genericDenial();
  const session = await findApplicationSession(client, requireString(body.sessionToken));
  const now = Date.now();
  if (!session || session.revoked_at || Date.parse(session.idle_expires_at) <= now || Date.parse(session.absolute_expires_at) <= now) return genericDenial();
  if (!await isSourceSessionActive(session.source_session_id, session.user_id)) {
    await revokeStoredSession(session, "source_session_inactive");
    return genericDenial();
  }
  const principal = await getLivePrincipal(session.user_id);
  if (!principal) {
    await revokeStoredSession(session, "account_inactive");
    return genericDenial();
  }
  if (principal.role !== session.trusted_role || !privilegesMatch(principal.privileges, session.trusted_privileges)) {
    await revokeStoredSession(session, "role_changed");
    return genericDenial();
  }
  const standardIdleMs = principal.role === "admin" ? 30 * 60 * 1000 : 24 * 60 * 60 * 1000;
  const nextIdle = new Date(Math.min(now + standardIdleMs, Date.parse(session.absolute_expires_at))).toISOString();
  await supabase.from("grameee_application_sessions").update({ last_seen_at: new Date(now).toISOString(), idle_expires_at: nextIdle }).eq("application_session_id", session.application_session_id).is("revoked_at", null);
  return json({
    active: true,
    session: { audience: session.audience, idleExpiresAt: nextIdle, absoluteExpiresAt: session.absolute_expires_at },
    principal,
  });
}

async function handleRevoke(request: Request, body: Record<string, unknown>) {
  const client = await authenticateClient(request, body.clientId);
  if (!client) return genericDenial();
  const session = await findApplicationSession(client, requireString(body.sessionToken));
  if (session && !session.revoked_at) {
    await revokeStoredSession(session, "local_logout");
    await writeAudit({
      event_type: "revoke",
      outcome: "revoked",
      application_session_id: session.application_session_id,
      user_id: session.user_id,
      client_id: client.client_id,
      audience: client.audience,
      reason: "local_logout",
      request_context_hash: await requestContextHash(request),
    });
  }
  return json({ ok: true });
}

Deno.serve(async (request) => {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: responseHeaders });
  if (request.method !== "POST") return json({ error: "Method not allowed." }, 405);
  if (!supabaseUrl || !serviceRoleKey || exchangeHmacSecret.length < 32) return json({ error: "Session exchange is unavailable." }, 503);

  const contentLength = Number.parseInt(request.headers.get("content-length") || "0", 10);
  if (Number.isFinite(contentLength) && contentLength > maxBodyBytes) return json({ error: "Request is too large." }, 413);
  const rawBody = await request.text();
  if (new TextEncoder().encode(rawBody).byteLength > maxBodyBytes) return json({ error: "Request is too large." }, 413);
  let body: Record<string, unknown>;
  try {
    body = JSON.parse(rawBody || "{}");
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }
  const action = requireString(body.action);
  if (action === "health") return json({ ok: true, enabled: await isEnabled() });
  if (!await isEnabled()) return json({ error: "Session exchange is disabled." }, 503);

  try {
    if (action === "issue") return await handleIssue(request, body);
    if (action === "redeem") return await handleRedeem(request, body);
    if (action === "validate") return await handleValidate(request, body);
    if (action === "revoke") return await handleRevoke(request, body);
    return json({ error: "Unknown session exchange action." }, 400);
  } catch {
    console.error("Session exchange request failed.");
    return json({ error: "Session exchange is temporarily unavailable." }, 503);
  }
});
