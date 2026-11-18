import { createClient } from "npm:@supabase/supabase-js@2";
import {
  ToolSubmissionValidationError,
  validateToolSubmission,
} from "./tool-submission-validation.mjs";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const serviceRoleKey = Deno.env.get("GRAMEEE_SERVICE_ROLE_KEY") ?? "";
const gmailClientId = Deno.env.get("GMAIL_CLIENT_ID") ?? "";
const gmailClientSecret = Deno.env.get("GMAIL_CLIENT_SECRET") ?? "";
const gmailRefreshToken = Deno.env.get("GMAIL_REFRESH_TOKEN") ?? "";
const gmailSenderEmail = Deno.env.get("GMAIL_SENDER_EMAIL") ?? "";
const gmailNotifyRecipient = Deno.env.get("GMAIL_NOTIFY_RECIPIENT") ?? "";
const frameworkDownloadRecipient = "climaterise@dasra.org";
const consortiumEmailBccRecipients = "tanmay.mukherji@rainmatter.org, thejaswinibs@rainmatter.org";
const consortiumEmailTemplateKey = "consortium_email_template";
const consortiumEmailSubject = "GramEEE Consortium Enquiry";
const defaultConsortiumEmailTemplate = [
  "Hello, I am interested in knowing more about the GramEEE consortium. Would like to connect with your team.",
  "",
  "Regards,",
  "{{userName}}",
].join("\n");
const impactCounterKeys = ["solutions_discovered", "connections_made"] as const;
type ImpactCounterKey = typeof impactCounterKeys[number];
const defaultImpactCounters: Record<ImpactCounterKey, number> = {
  solutions_discovered: 0,
  connections_made: 0,
};
const impactCounterStorageEmail = "tanmay@greenruraleconomy.in";
const impactViewAuditLogKey = "impact_view_audit_log";
const impactEmailAuditLogKey = "impact_email_audit_log";
const maxImpactAuditEntries = 2500;

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

function normalizeImpactCounterKey(value: unknown): ImpactCounterKey | "" {
  const normalized = requireString(value).toLowerCase();
  return (impactCounterKeys as readonly string[]).includes(normalized)
    ? normalized as ImpactCounterKey
    : "";
}

function coerceNonNegativeInteger(value: unknown, fallback = 0) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.max(0, Math.round(parsed));
}

function normalizeRole(value: unknown) {
  const normalized = requireString(value).toLowerCase();
  return ["admin", "moderator", "curator", "user"].includes(normalized) ? normalized : "user";
}

function sanitizeAuditText(value: unknown, fallback = "", maxLength = 500) {
  const text = requireString(value) || fallback;
  return text.slice(0, maxLength);
}

function normalizeEmailList(value: unknown) {
  return requireString(value)
    .split(",")
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean)
    .filter((item, index, list) => list.indexOf(item) === index)
    .join(", ");
}

function isValidEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

async function listAuthUsers() {
  const users: Record<string, unknown>[] = [];
  let page = 1;
  const perPage = 200;

  while (true) {
    const { data, error } = await supabase.auth.admin.listUsers({
      page,
      perPage,
    });

    if (error) {
      throw new Error(`Users could not be loaded: ${error.message}`);
    }

    const batch = Array.isArray(data?.users) ? data.users : [];
    users.push(...batch as Record<string, unknown>[]);

    if (batch.length < perPage) {
      break;
    }

    page += 1;
  }

  return users;
}

function getUserAppMetadata(user: Record<string, unknown>) {
  return ((user.app_metadata || user.raw_app_meta_data || {}) as Record<string, unknown>);
}

function getUserMetadata(user: Record<string, unknown>) {
  return ((user.user_metadata || user.raw_user_meta_data || {}) as Record<string, unknown>);
}

async function findImpactCounterStorageUser() {
  const users = await listAuthUsers();
  const byEmail = users.find((user) => {
    const email = requireString(user.email).toLowerCase();
    return email === impactCounterStorageEmail;
  }) as Record<string, unknown> | undefined;

  if (byEmail) {
    return byEmail;
  }

  return users.find((user) => {
    const username = requireString(getUserMetadata(user).username).toLowerCase();
    return username === "admin";
  }) as Record<string, unknown> | undefined;
}

async function findSharedStorageUser() {
  const user = await findImpactCounterStorageUser();

  if (!user?.id) {
    throw new Error("Shared storage user could not be found.");
  }

  return user;
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

function toBase64Url(input: string) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

async function getGmailAccessToken() {
  if (!gmailClientId || !gmailClientSecret || !gmailRefreshToken) {
    throw new Error("Gmail secrets are not configured.");
  }

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: gmailClientId,
      client_secret: gmailClientSecret,
      refresh_token: gmailRefreshToken,
      grant_type: "refresh_token",
    }),
  });

  const data = await response.json().catch(() => null);

  if (!response.ok || !data?.access_token) {
    throw new Error(data?.error_description || data?.error || "Could not refresh Gmail access token.");
  }

  return String(data.access_token);
}

async function sendProcessorNotification(processorName: string) {
  if (!gmailSenderEmail || !gmailNotifyRecipient) {
    throw new Error("Gmail sender or recipient is not configured.");
  }

  const accessToken = await getGmailAccessToken();
  const subject = "New Processor Added, please validate";
  const bodyLines = [
    "New Processor Added, please validate",
    "",
    `Processor: ${processorName || "Unnamed Processor"}`,
    `Submitted At: ${new Date().toISOString()}`,
  ];

  const rawMessage = [
    `From: ${gmailSenderEmail}`,
    `To: ${gmailNotifyRecipient}`,
    `Subject: ${subject}`,
    "Content-Type: text/plain; charset=UTF-8",
    "",
    bodyLines.join("\n"),
  ].join("\r\n");

  const response = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      raw: toBase64Url(rawMessage),
    }),
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(data?.error?.message || "Gmail notification could not be sent.");
  }

  return data;
}

async function sendFrameworkDownloadNotification(name: string, email: string, phone: string, sourceUrl: string) {
  if (!gmailSenderEmail || !frameworkDownloadRecipient) {
    throw new Error("Framework download recipient is not configured.");
  }

  const accessToken = await getGmailAccessToken();
  const subject = "New Framework Download";
  const bodyLines = [
    "New framework download request received.",
    "",
    `Name: ${name}`,
    `Email: ${email}`,
    `Phone: ${phone || "Not provided"}`,
    `Page: ${sourceUrl || "Not provided"}`,
    `Submitted At: ${new Date().toISOString()}`,
  ];

  const rawMessage = [
    `From: ${gmailSenderEmail}`,
    `To: ${frameworkDownloadRecipient}`,
    `Subject: ${subject}`,
    "Content-Type: text/plain; charset=UTF-8",
    "",
    bodyLines.join("\n"),
  ].join("\r\n");

  const response = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      raw: toBase64Url(rawMessage),
    }),
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(data?.error?.message || "Gmail notification could not be sent.");
  }

  return data;
}

function renderConsortiumEmailTemplate(template: string, senderName: string) {
  const normalizedTemplate = requireString(template) || defaultConsortiumEmailTemplate;
  const fallbackName = requireString(senderName) || "Interested User";
  return normalizedTemplate.replaceAll("{{userName}}", fallbackName);
}

async function sendConsortiumEmailNotification(senderName: string, senderEmail: string, bodyText: string) {
  if (!gmailSenderEmail || !frameworkDownloadRecipient) {
    throw new Error("Consortium email sender or recipient is not configured.");
  }

  const accessToken = await getGmailAccessToken();
  const rawMessage = [
    `From: ${gmailSenderEmail}`,
    `To: ${frameworkDownloadRecipient}`,
    `Cc: ${senderEmail}`,
    `Bcc: ${consortiumEmailBccRecipients}`,
    `Reply-To: ${senderEmail}`,
    `Subject: ${consortiumEmailSubject}`,
    "Content-Type: text/plain; charset=UTF-8",
    "",
    bodyText,
  ].join("\r\n");

  const response = await fetch("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      raw: toBase64Url(rawMessage),
    }),
  });

  const data = await response.json().catch(() => null);

  if (!response.ok) {
    throw new Error(data?.error?.message || "Consortium email could not be sent.");
  }

  return data;
}

async function handleFrameworkDownload(name: string, email: string, phone: string, sourceUrl: string) {
  if (!name || !email) {
    return errorResponse("Name and email are required.", 400);
  }

  try {
    await sendFrameworkDownloadNotification(name, email, phone, sourceUrl);
    return jsonResponse({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Framework download notification failed.";
    return errorResponse(message, 500);
  }
}

async function loadConsortiumEmailTemplate() {
  const storageUser = await findSharedStorageUser();
  const appMetadata = getUserAppMetadata(storageUser);
  return requireString(appMetadata[consortiumEmailTemplateKey]) || defaultConsortiumEmailTemplate;
}

async function saveConsortiumEmailTemplate(nextTemplate: string) {
  const storageUser = await findSharedStorageUser();
  const currentAppMetadata = getUserAppMetadata(storageUser);
  const { error } = await supabase.auth.admin.updateUserById(String(storageUser.id), {
    app_metadata: {
      ...currentAppMetadata,
      [consortiumEmailTemplateKey]: requireString(nextTemplate) || defaultConsortiumEmailTemplate,
    },
  });

  if (error) {
    throw new Error(error.message || "Consortium email template could not be saved.");
  }
}

async function resolveConsortiumSender(authHeader: string, name: string, email: string) {
  const bearerToken = requireString(authHeader.replace(/^Bearer\s+/i, ""));

  if (bearerToken && bearerToken !== serviceRoleKey) {
    try {
      const user = await verifyBearerUser(authHeader);
      const metadata = getUserMetadata(user as Record<string, unknown>);
      const senderName = requireString(metadata.full_name) || requireString(metadata.username) || requireString(user.email);
      const senderEmail = requireString(user.email);

      if (senderName && senderEmail && isValidEmail(senderEmail)) {
        return { senderName, senderEmail, source: "session" as const };
      }
    } catch {
      // Fall back to guest payload when shared session hydration lags on the client.
    }
  }

  const senderName = requireString(name);
  const senderEmail = requireString(email).toLowerCase();

  if (!senderName || !senderEmail || !isValidEmail(senderEmail)) {
    throw new Error("Name and a valid email address are required.");
  }

  return { senderName, senderEmail, source: "guest" as const };
}

async function buildConsortiumEmailPreview(authHeader: string, name: string, email: string) {
  const sender = await resolveConsortiumSender(authHeader, name, email);
  const template = await loadConsortiumEmailTemplate();
  const body = renderConsortiumEmailTemplate(template, sender.senderName);

  return {
    from: gmailSenderEmail,
    to: frameworkDownloadRecipient,
    cc: sender.senderEmail,
    bcc: consortiumEmailBccRecipients,
    replyTo: sender.senderEmail,
    subject: consortiumEmailSubject,
    body,
    senderName: sender.senderName,
    senderEmail: sender.senderEmail,
    template,
  };
}

async function handleGetConsortiumEmailTemplate(token: string, authHeader: string) {
  try {
    await resolveAdminAccess(token, authHeader);
    const template = await loadConsortiumEmailTemplate();
    return jsonResponse({ template });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Consortium email template could not be loaded.";
    return errorResponse(message, 500);
  }
}

async function handleSaveConsortiumEmailTemplate(token: string, authHeader: string, template: string) {
  try {
    await resolveAdminAccess(token, authHeader);
    await saveConsortiumEmailTemplate(template);
    return jsonResponse({ ok: true, template: await loadConsortiumEmailTemplate() });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Consortium email template could not be saved.";
    return errorResponse(message, 500);
  }
}

async function handlePreviewConsortiumEmail(authHeader: string, name: string, email: string) {
  try {
    return jsonResponse({
      ok: true,
      preview: await buildConsortiumEmailPreview(authHeader, name, email),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Consortium email preview could not be prepared.";
    return errorResponse(message, 400);
  }
}

async function handleSendConsortiumEmail(authHeader: string, name: string, email: string) {
  try {
    const preview = await buildConsortiumEmailPreview(authHeader, name, email);
    await sendConsortiumEmailNotification(preview.senderName, preview.senderEmail, preview.body);
    await appendImpactEmailAuditEntry({
      surface: "grameee",
      action: "consortium_outreach",
      counterKey: "connections_made",
      senderEmail: preview.senderEmail,
      senderName: preview.senderName,
      recipientEmail: frameworkDownloadRecipient,
      ccEmail: preview.senderEmail,
      bccEmail: preview.bcc,
      replyTo: preview.senderEmail,
      subject: consortiumEmailSubject,
      itemLabel: "GramEEE consortium",
      itemSource: "grameee-homepage",
    });
    return jsonResponse({ ok: true, preview });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Consortium email could not be sent.";
    return errorResponse(message, 500);
  }
}

async function loadImpactCounters() {
  const counters = { ...defaultImpactCounters };

  const storageUser = await findImpactCounterStorageUser();
  const appMetadata = storageUser ? getUserAppMetadata(storageUser) : {};
  const storedCounters = appMetadata.impact_counters && typeof appMetadata.impact_counters === "object"
    ? appMetadata.impact_counters as Record<string, unknown>
    : {};

  for (const key of impactCounterKeys) {
    counters[key] = coerceNonNegativeInteger(storedCounters[key], defaultImpactCounters[key]);
  }

  return counters;
}

async function saveImpactCounters(nextCounters: Record<ImpactCounterKey, number>) {
  const storageUser = await findImpactCounterStorageUser();

  if (!storageUser?.id) {
    throw new Error("Impact counter storage user could not be found.");
  }

  const currentAppMetadata = getUserAppMetadata(storageUser);
  const { error } = await supabase.auth.admin.updateUserById(String(storageUser.id), {
    app_metadata: {
      ...currentAppMetadata,
      impact_counters: {
        solutions_discovered: coerceNonNegativeInteger(nextCounters.solutions_discovered),
        connections_made: coerceNonNegativeInteger(nextCounters.connections_made),
      },
    },
  });

  if (error) {
    throw new Error(error.message || "Impact counters could not be saved.");
  }
}

async function getGreMisSettingRecord(key: string) {
  const { data, error } = await supabase
    .from("gre_mis_settings")
    .select("key, value_json, updated_by_email, updated_at")
    .eq("key", key)
    .maybeSingle();

  if (error) {
    throw new Error(error.message || `GRE MIS setting ${key} could not be loaded.`);
  }

  return data as Record<string, unknown> | null;
}

async function upsertGreMisSettingRecord(
  key: string,
  valueJson: Record<string, unknown>,
  updatedByEmail: string,
) {
  const { error } = await supabase
    .from("gre_mis_settings")
    .upsert({
      key,
      value_text: null,
      value_json: valueJson,
      updated_by_email: updatedByEmail || null,
      updated_at: new Date().toISOString(),
    });

  if (error) {
    throw new Error(error.message || `GRE MIS setting ${key} could not be saved.`);
  }
}

async function appendImpactAuditEntry(
  key: string,
  entry: Record<string, unknown>,
  updatedByEmail: string,
) {
  try {
    const current = await getGreMisSettingRecord(key);
    const currentValue = current?.value_json && typeof current.value_json === "object"
      ? current.value_json as Record<string, unknown>
      : {};
    const currentEntries = Array.isArray(currentValue.entries) ? currentValue.entries : [];
    const entries = [entry, ...currentEntries].slice(0, maxImpactAuditEntries);
    await upsertGreMisSettingRecord(key, { entries }, updatedByEmail || "system:audit");
  } catch (error) {
    console.warn("Impact audit log append failed", error);
  }
}

async function appendImpactViewAuditEntry(event: Record<string, unknown>) {
  const actorEmail = sanitizeAuditText(event.actorEmail, "anonymous", 320).toLowerCase();
  const actorName = sanitizeAuditText(event.actorName, actorEmail || "Anonymous Viewer", 320);
  await appendImpactAuditEntry(impactViewAuditLogKey, {
    id: crypto.randomUUID(),
    logged_at: new Date().toISOString(),
    kind: "view",
    surface: sanitizeAuditText(event.surface, "unknown", 120),
    action: sanitizeAuditText(event.action, "view_details", 120),
    counter_key: sanitizeAuditText(event.counterKey, "solutions_discovered", 80),
    actor_email: actorEmail,
    actor_name: actorName,
    actor_role: sanitizeAuditText(event.actorRole, "", 80),
    item_id: sanitizeAuditText(event.itemId, "", 200),
    item_label: sanitizeAuditText(event.itemLabel, "", 500),
    item_source: sanitizeAuditText(event.itemSource, "", 200),
    portal_url: sanitizeAuditText(event.portalUrl, "", 1000),
    source_page: sanitizeAuditText(event.sourcePage, "", 1000),
  }, actorEmail || "system:view-audit");
}

async function appendImpactEmailAuditEntry(event: Record<string, unknown>) {
  const senderEmail = sanitizeAuditText(event.senderEmail, "unknown", 320).toLowerCase();
  const senderName = sanitizeAuditText(event.senderName, senderEmail || "Unknown Sender", 320);
  await appendImpactAuditEntry(impactEmailAuditLogKey, {
    id: crypto.randomUUID(),
    logged_at: new Date().toISOString(),
    kind: "email",
    surface: sanitizeAuditText(event.surface, "unknown", 120),
    action: sanitizeAuditText(event.action, "email", 120),
    counter_key: sanitizeAuditText(event.counterKey, "connections_made", 80),
    sender_email: senderEmail,
    sender_name: senderName,
    sender_role: sanitizeAuditText(event.senderRole, "", 80),
    recipient_email: sanitizeAuditText(event.recipientEmail, "", 320).toLowerCase(),
    cc_email: normalizeEmailList(event.ccEmail),
    reply_to: sanitizeAuditText(event.replyTo, "", 320).toLowerCase(),
    subject: sanitizeAuditText(event.subject, "", 500),
    item_id: sanitizeAuditText(event.itemId, "", 200),
    item_label: sanitizeAuditText(event.itemLabel, "", 500),
    item_source: sanitizeAuditText(event.itemSource, "", 200),
    need_id: sanitizeAuditText(event.needId, "", 120),
    provider_name: sanitizeAuditText(event.providerName, "", 320),
    seeker_name: sanitizeAuditText(event.seekerName, "", 320),
  }, senderEmail || "system:email-audit");
}

async function handleGetImpactCounters() {
  try {
    const counters = await loadImpactCounters();
    return jsonResponse({ counters });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Impact counters could not be loaded.";
    return errorResponse(message, 500);
  }
}

async function handleIncrementImpactCounter(counterKey: string, delta: number, auditEvent: Record<string, unknown> | null = null) {
  const normalizedCounterKey = normalizeImpactCounterKey(counterKey);

  if (!normalizedCounterKey) {
    return errorResponse("A valid impact counter key is required.", 400);
  }

  try {
    const counters = await loadImpactCounters();
    counters[normalizedCounterKey] = coerceNonNegativeInteger(counters[normalizedCounterKey]) + Math.max(1, coerceNonNegativeInteger(delta, 1));
    await saveImpactCounters(counters);
    if (auditEvent && typeof auditEvent === "object") {
      const eventKind = sanitizeAuditText(auditEvent.kind, "", 40).toLowerCase();
      if (eventKind === "view") {
        await appendImpactViewAuditEntry({
          ...auditEvent,
          counterKey: normalizedCounterKey,
        });
      } else if (eventKind === "email") {
        await appendImpactEmailAuditEntry({
          ...auditEvent,
          counterKey: normalizedCounterKey,
        });
      }
    }
    const refreshed = await loadImpactCounters();
    return jsonResponse({ ok: true, counters: refreshed });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Impact counter could not be updated.";
    return errorResponse(message, 500);
  }
}

async function handleUpdateImpactCounters(
  token: string,
  authHeader: string,
  solutionsDiscovered: number,
  connectionsMade: number,
) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  try {
    const nextSolutions = coerceNonNegativeInteger(solutionsDiscovered);
    const nextConnections = coerceNonNegativeInteger(connectionsMade);
    await saveImpactCounters({
      solutions_discovered: nextSolutions,
      connections_made: nextConnections,
    });
    const counters = await loadImpactCounters();
    return jsonResponse({ ok: true, counters });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Impact counters could not be saved.";
    return errorResponse(message, 500);
  }
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

async function verifyBearerUser(authHeader: string) {
  const token = requireString(authHeader.replace(/^Bearer\s+/i, ""));

  if (!token) {
    throw new Error("User session is missing.");
  }

  const { data, error } = await supabase.auth.getUser(token);

  if (error || !data?.user) {
    throw new Error("User session is invalid.");
  }

  if (data.user.user_metadata?.grameee_removed === true || data.user.app_metadata?.grameee_removed === true) {
    throw new Error("This GramEEE user record has been removed.");
  }

  return data.user;
}

async function resolveAdminAccess(token: string, authHeader: string) {
  if (token) {
    const session = await validateSession(token);

    if (!session) {
      throw new Error("Invalid admin session.");
    }

    return {
      username: session.username,
    };
  }

  const user = await verifyBearerUser(authHeader);
  const role = normalizeRole(user.app_metadata?.grameee_role);

  if (role !== "admin") {
    throw new Error("Admin access is required.");
  }

  return {
    username: requireString(user.user_metadata?.username) || requireString(user.email) || "admin",
  };
}

async function verifyAdminPassword(username: string, password: string) {
  const { data, error } = await supabase.rpc("grameee_admin_password_matches", {
    p_username: username,
    p_password: password,
  });

  if (error) {
    throw new Error(`Admin password verification failed: ${error.message}`);
  }

  return Boolean(data);
}

async function createAdminPasswordHash(password: string) {
  const { data, error } = await supabase.rpc("grameee_hash_admin_password", {
    p_password: password,
  });

  if (error || typeof data !== "string" || !data) {
    throw new Error(error?.message || "Admin password hash could not be generated.");
  }

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

  let validPassword = false;

  try {
    validPassword = await verifyAdminPassword("admin", password);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Admin password verification failed.";
    return errorResponse(message, 500);
  }

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

async function handleListPending(token: string, authHeader: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleSubmitTool(body: Record<string, unknown>) {
  let submission;
  try {
    submission = validateToolSubmission(body);
  } catch (error) {
    if (error instanceof ToolSubmissionValidationError) {
      return errorResponse(error.message, 400);
    }
    return errorResponse("Tool submission is invalid.", 400);
  }

  const { data: flag, error: flagError } = await supabase
    .from("grameee_security_flags")
    .select("enabled, user_message")
    .eq("flag_key", "public_tool_submission_enabled")
    .maybeSingle();

  if (flagError || flag?.enabled !== true) {
    return errorResponse(
      requireString(flag?.user_message)
        || "New tool submissions are temporarily unavailable.",
      503,
    );
  }

  const { error } = await supabase
    .from("grameee_tools")
    .insert(submission);

  if (error) {
    console.error("Validated tool submission could not be saved", {
      code: error.code,
      message: error.message,
    });
    return errorResponse("The submission could not be saved right now.", 500);
  }

  return jsonResponse({ ok: true }, 201);
}

async function handleListAll(token: string, authHeader: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function deleteGalleryStorageObject(imagePath: string | null) {
  if (!imagePath) {
    return;
  }

  await supabase.storage.from("grameee-gallery").remove([imagePath]);
}

async function handleListPendingGallery(token: string, authHeader: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  const { data, error } = await supabase
    .from("grameee_gallery_items")
    .select("id, label, description, image_path, status, created_at")
    .eq("status", "pending")
    .order("created_at", { ascending: true });

  if (error) {
    return errorResponse("Pending gallery uploads could not be loaded.", 500);
  }

  return jsonResponse({ items: data ?? [] });
}

async function handleListAllGallery(token: string, authHeader: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  const { data, error } = await supabase
    .from("grameee_gallery_items")
    .select("id, label, description, image_path, status, created_at")
    .eq("status", "approved")
    .order("created_at", { ascending: false });

  if (error) {
    return errorResponse("Approved gallery images could not be loaded.", 500);
  }

  return jsonResponse({ items: data ?? [] });
}

async function handleCreateGallery(
  token: string,
  authHeader: string,
  label: string,
  description: string,
  imagePath: string,
) {
  let session;

  try {
    session = await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  if (!label || !imagePath) {
    return errorResponse("Gallery label and image path are required.", 400);
  }

  const { error } = await supabase
    .from("grameee_gallery_items")
    .insert({
      label,
      description: description || null,
      image_path: imagePath,
      status: "approved",
      approved_at: new Date().toISOString(),
      approved_by_email: session.username,
    });

  if (error) {
    return errorResponse("Gallery image could not be created.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleListPendingProcessors(token: string, authHeader: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleListAllProcessors(token: string, authHeader: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleApprove(token: string, authHeader: string, toolId: string) {
  let session;

  try {
    session = await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleReject(token: string, authHeader: string, toolId: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleDeleteTool(token: string, authHeader: string, toolId: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleApproveGallery(token: string, authHeader: string, galleryId: string) {
  let session;

  try {
    session = await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  const { error } = await supabase
    .from("grameee_gallery_items")
    .update({
      status: "approved",
      approved_at: new Date().toISOString(),
      approved_by_email: session.username,
      updated_at: new Date().toISOString(),
    })
    .eq("id", galleryId);

  if (error) {
    return errorResponse("Gallery image could not be approved.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleRejectGallery(token: string, authHeader: string, galleryId: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  const { data, error } = await supabase
    .from("grameee_gallery_items")
    .select("image_path")
    .eq("id", galleryId)
    .maybeSingle();

  if (error) {
    return errorResponse("Gallery image could not be loaded.", 500);
  }

  await deleteGalleryStorageObject(data?.image_path ?? null);

  const { error: deleteError } = await supabase
    .from("grameee_gallery_items")
    .delete()
    .eq("id", galleryId);

  if (deleteError) {
    return errorResponse("Gallery image could not be rejected.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleDeleteGallery(token: string, authHeader: string, galleryId: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  const { data, error } = await supabase
    .from("grameee_gallery_items")
    .select("image_path")
    .eq("id", galleryId)
    .maybeSingle();

  if (error) {
    return errorResponse("Gallery image could not be loaded.", 500);
  }

  await deleteGalleryStorageObject(data?.image_path ?? null);

  const { error: deleteError } = await supabase
    .from("grameee_gallery_items")
    .delete()
    .eq("id", galleryId);

  if (deleteError) {
    return errorResponse("Gallery image could not be deleted.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleUpdateGallery(
  token: string,
  authHeader: string,
  galleryId: string,
  label: string,
  description: string,
) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  if (!galleryId || !label) {
    return errorResponse("Gallery id and label are required.", 400);
  }

  const { error } = await supabase
    .from("grameee_gallery_items")
    .update({
      label,
      description: description || null,
      updated_at: new Date().toISOString(),
    })
    .eq("id", galleryId);

  if (error) {
    return errorResponse("Gallery image text could not be updated.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleUpdateTool(
  token: string,
  authHeader: string,
  toolId: string,
  name: string,
  url: string,
  category: string,
  description: string,
) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  if (!toolId || !name || !url) {
    return errorResponse("Tool id, name, and URL are required.", 400);
  }

  const { error } = await supabase
    .from("grameee_tools")
    .update({
      name,
      url,
      category: category || null,
      description: description || null,
      updated_at: new Date().toISOString(),
    })
    .eq("id", toolId);

  if (error) {
    return errorResponse("Tool could not be updated.", 500);
  }

  return jsonResponse({ ok: true });
}

async function handleApproveProcessor(token: string, authHeader: string, processorId: string) {
  let session;

  try {
    session = await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleRejectProcessor(token: string, authHeader: string, processorId: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleDeleteProcessor(token: string, authHeader: string, processorId: string) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
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

async function handleUpdateProcessor(
  token: string,
  authHeader: string,
  processorId: string,
  name: string,
  inputs: string[],
  outputs: string[],
  processingTime: string,
  description: string,
) {
  try {
    await resolveAdminAccess(token, authHeader);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid admin session.";
    return errorResponse(message, 401);
  }

  const cleanedInputs = inputs.map((item) => item.trim()).filter(Boolean);
  const cleanedOutputs = outputs.map((item) => item.trim()).filter(Boolean);

  if (!processorId || !name || !cleanedInputs.length || !cleanedOutputs.length) {
    return errorResponse("Processor id, name, inputs, and outputs are required.", 400);
  }

  const { error } = await supabase
    .from("processors")
    .update({
      name,
      inputs: cleanedInputs,
      outputs: cleanedOutputs,
      processing_time: processingTime || null,
      description: description || null,
      updated_at: new Date().toISOString(),
    })
    .eq("id", processorId);

  if (error) {
    return errorResponse(`Processor could not be updated: ${error.message}`, 500);
  }

  return jsonResponse({ ok: true });
}

async function handleNotifyNewProcessor(processorName: string) {
  try {
    await sendProcessorNotification(processorName);
    return jsonResponse({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Processor notification failed.";
    return errorResponse(message, 500);
  }
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

  let validPassword = false;

  try {
    validPassword = await verifyAdminPassword(session.username, currentPassword);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Current admin password could not be verified.";
    return errorResponse(message, 500);
  }

  if (!validPassword) {
    return errorResponse("Current password is incorrect.", 401);
  }

  let nextHash = "";

  try {
    nextHash = await createAdminPasswordHash(newPassword);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Admin password hash could not be generated.";
    return errorResponse(message, 500);
  }

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
  const galleryId = requireString(body.galleryId);
  const name = requireString(body.name);
  const label = requireString(body.label);
  const url = requireString(body.url);
  const category = requireString(body.category);
  const description = requireString(body.description);
  const imagePath = requireString(body.imagePath);
  const processorId = requireString(body.processorId);
  const processorName = requireString(body.processorName);
  const email = requireString(body.email);
  const phone = requireString(body.phone);
  const sourceUrl = requireString(body.sourceUrl);
  const template = String(body.template ?? "");
  const counterKey = requireString(body.counterKey);
  const delta = coerceNonNegativeInteger(body.delta, 1);
  const solutionsDiscovered = coerceNonNegativeInteger(body.solutionsDiscovered);
  const connectionsMade = coerceNonNegativeInteger(body.connectionsMade);
  const authHeader = request.headers.get("Authorization") || "";
  const inputs = Array.isArray(body.inputs) ? body.inputs.filter((item): item is string => typeof item === "string") : [];
  const outputs = Array.isArray(body.outputs) ? body.outputs.filter((item): item is string => typeof item === "string") : [];
  const processingTime = requireString(body.processingTime);

  switch (action) {
    case "submitTool":
      return await handleSubmitTool(body);
    case "login":
      return await handleLogin(password);
    case "verify":
      return await handleVerify(token);
    case "listPendingProcessors":
      return await handleListPendingProcessors(token, authHeader);
    case "listAllProcessors":
      return await handleListAllProcessors(token, authHeader);
    case "approveProcessor":
      return await handleApproveProcessor(token, authHeader, processorId);
    case "rejectProcessor":
      return await handleRejectProcessor(token, authHeader, processorId);
    case "deleteProcessor":
      return await handleDeleteProcessor(token, authHeader, processorId);
    case "updateProcessor":
      return await handleUpdateProcessor(token, authHeader, processorId, name, inputs, outputs, processingTime, description);
    case "notifyNewProcessor":
      return await handleNotifyNewProcessor(processorName);
    case "frameworkDownload":
      return await handleFrameworkDownload(name, email, phone, sourceUrl);
    case "getConsortiumEmailTemplate":
      return await handleGetConsortiumEmailTemplate(token, authHeader);
    case "saveConsortiumEmailTemplate":
      return await handleSaveConsortiumEmailTemplate(token, authHeader, template);
    case "previewConsortiumEmail":
      return await handlePreviewConsortiumEmail(authHeader, name, email);
    case "sendConsortiumEmail":
      return await handleSendConsortiumEmail(authHeader, name, email);
    case "getImpactCounters":
      return await handleGetImpactCounters();
    case "incrementImpactCounter":
      return await handleIncrementImpactCounter(
        counterKey,
        delta,
        body.auditEvent && typeof body.auditEvent === "object" ? body.auditEvent as Record<string, unknown> : null,
      );
    case "listPending":
      return await handleListPending(token, authHeader);
    case "listAll":
      return await handleListAll(token, authHeader);
    case "listPendingGallery":
      return await handleListPendingGallery(token, authHeader);
    case "listAllGallery":
      return await handleListAllGallery(token, authHeader);
    case "createGallery":
      return await handleCreateGallery(token, authHeader, name || label, description, imagePath);
    case "approve":
      return await handleApprove(token, authHeader, toolId);
    case "reject":
      return await handleReject(token, authHeader, toolId);
    case "deleteTool":
      return await handleDeleteTool(token, authHeader, toolId);
    case "approveGallery":
      return await handleApproveGallery(token, authHeader, galleryId);
    case "rejectGallery":
      return await handleRejectGallery(token, authHeader, galleryId);
    case "deleteGallery":
      return await handleDeleteGallery(token, authHeader, galleryId);
    case "updateGallery":
      return await handleUpdateGallery(token, authHeader, galleryId, name || label, description);
    case "updateTool":
      return await handleUpdateTool(token, authHeader, toolId, name, url, category, description);
    case "updateImpactCounters":
      return await handleUpdateImpactCounters(token, authHeader, solutionsDiscovered, connectionsMade);
    case "changePassword":
      return await handleChangePassword(token, currentPassword, newPassword);
    case "logout":
      return await handleLogout(token);
    default:
      return errorResponse("Unknown admin action.", 400);
  }
});
