import { createClient } from "npm:@supabase/supabase-js@2";
import { completePasswordResetSecurity } from "./recovery-security.mjs";
import {
  buildRateLimitKey,
  buildRecoveryDecoyTarget,
  claimConsumedVerification,
  createVerificationMaterial,
  normalizeVerificationPurpose,
  normalizeVerificationTarget,
  verifyVerificationTransaction,
} from "./verification.mjs";

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
const helpGmailClientId = Deno.env.get("HELP_GMAIL_CLIENT_ID") ?? gmailClientId;
const helpGmailClientSecret = Deno.env.get("HELP_GMAIL_CLIENT_SECRET") ?? gmailClientSecret;
const helpGmailRefreshToken = Deno.env.get("HELP_GMAIL_REFRESH_TOKEN") ?? gmailRefreshToken;
const helpGmailSenderEmail = Deno.env.get("HELP_GMAIL_SENDER_EMAIL") ?? "help@greenruraleconomy.in";
const otpHmacSecret = Deno.env.get("GRAMEEE_OTP_HMAC_SECRET") ?? "";
const publicAnonKey = Deno.env.get("GRAMEEE_SUPABASE_ANON_KEY")
  ?? "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InpwaGFiZXpxYmJvYWV4bW1oY2ljIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzYxNTY5MTgsImV4cCI6MjA5MTczMjkxOH0.cHZCuzwiAEEQjPo6WAADaD5oBZapFmk45dOe4A4g37U";

const staticOrganizations = [
  "Buzz Women",
  "OASIS Social Innovations Lab",
  "PRADAN",
  "Transform Rural India Foundation",
  "Rainmatter Foundation",
  "CEEW",
  "Jagriti Enterprise Centre Purvanchal",
  "ClimateRISE Alliance",
  "Green Rural Economy",
  "Sobus Insight Forum",
  "Lipok Social Foundation",
  "Puttannaiah Foundation",
  "Akshaykalpa",
];

const privilegeDefaults = {
  ecosystem: true,
  askGre: true,
  offerSolutions: true,
  askHelp: true,
  needsMap: true,
  gre: false,
};

const roleLabels = ["admin", "moderator", "curator", "user"] as const;
type GrameeeRole = typeof roleLabels[number];
const organisationRoleLabels = ["org_admin", "org_editor", "org_viewer"] as const;
type OrganisationRole = typeof organisationRoleLabels[number];

const AUTH_VERIFICATION_FLAG = "insecure_auth_verification_enabled";
const AUTH_VERIFICATION_MAINTENANCE_MESSAGE =
  "Account registration and password recovery are temporarily unavailable while we complete a security upgrade. Existing users can continue to sign in.";
const AUTH_VERIFICATION_ACTIONS = new Set([
  "sendEmailCode",
  "verifyEmailCode",
  "registerUser",
  "forgotPasswordStart",
  "forgotPasswordComplete",
]);

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

async function isSecurityFlagEnabled(flagKey: string) {
  const { data, error } = await supabase
    .from("grameee_security_flags")
    .select("enabled")
    .eq("flag_key", flagKey)
    .maybeSingle();

  if (error) {
    console.error("Security containment flag lookup failed; protected feature remains disabled.");
    return false;
  }

  return data?.enabled === true;
}

function requireString(value: unknown) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeEmail(value: string) {
  return value.trim().toLowerCase();
}

function normalizeUsername(value: string) {
  return value.trim().toLowerCase();
}

function normalizeOrganisationName(value: string) {
  return value.trim().replace(/\s+/g, " ").toLowerCase();
}

function getUserMetadata(user: Record<string, unknown>) {
  return ((user.user_metadata || user.raw_user_meta_data || {}) as Record<string, unknown>);
}

function getUserAppMetadata(user: Record<string, unknown>) {
  return ((user.app_metadata || user.raw_app_meta_data || {}) as Record<string, unknown>);
}

function normalizeRole(value: string): GrameeeRole {
  const normalized = requireString(value).toLowerCase();
  return (roleLabels as readonly string[]).includes(normalized) ? normalized as GrameeeRole : "user";
}

function isValidEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function isPasswordStrong(value: string) {
  return value.length >= 8 && /\d/.test(value) && /[^A-Za-z0-9]/.test(value);
}

function toBase64Url(input: string) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

type GmailCredentialSet = {
  clientId: string;
  clientSecret: string;
  refreshToken: string;
  senderEmail: string;
};

function getVerificationMailerCredentials(): GmailCredentialSet {
  return {
    clientId: helpGmailClientId,
    clientSecret: helpGmailClientSecret,
    refreshToken: helpGmailRefreshToken,
    senderEmail: helpGmailSenderEmail || gmailSenderEmail,
  };
}

async function getGmailAccessToken(credentials: GmailCredentialSet) {
  if (!credentials.clientId || !credentials.clientSecret || !credentials.refreshToken) {
    throw new Error("Gmail secrets are not configured.");
  }

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      client_id: credentials.clientId,
      client_secret: credentials.clientSecret,
      refresh_token: credentials.refreshToken,
      grant_type: "refresh_token",
    }),
  });

  const data = await response.json().catch(() => null);

  if (!response.ok || !data?.access_token) {
    throw new Error(data?.error_description || data?.error || "Could not refresh Gmail access token.");
  }

  return String(data.access_token);
}

async function sendMail(to: string, subject: string, bodyLines: string[]) {
  const credentials = getVerificationMailerCredentials();

  if (!credentials.senderEmail) {
    throw new Error("Gmail sender is not configured.");
  }

  const accessToken = await getGmailAccessToken(credentials);
  const rawMessage = [
    `From: ${credentials.senderEmail}`,
    `To: ${to}`,
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
    throw new Error(data?.error?.message || "Mail could not be sent.");
  }

  return data;
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

async function safeSelectStrings(table: string, column: string) {
  const { data, error } = await supabase
    .from(table)
    .select(column)
    .limit(5000);

  if (error) {
    console.warn(`Organization source ${table}.${column} could not be loaded: ${error.message}`);
    return [] as string[];
  }

  return (Array.isArray(data) ? data : [])
    .map((row) => requireString((row as Record<string, unknown>)[column]))
    .filter(Boolean);
}

async function loadKnownOrganizations() {
  const users = await listAuthUsers();
  const authOrganizations = users
    .map((user) => getUserOrganization(user as Record<string, unknown>))
    .filter(Boolean);

  const [
    ecosystemOrganizations,
    greSolutionProviderOrganizations,
    greSolutionProviderProductOrganizations,
    greMisTraderOrganizations,
    greMisOfferingOrganizations,
  ] = await Promise.all([
    safeSelectStrings("ecosystem_directory_entities", "entity_name"),
    safeSelectStrings("innovation_guild_vendors", "vendor_name"),
    safeSelectStrings("innovation_guild_products", "vendor_name"),
    safeSelectStrings("traders", "organisation_name"),
    safeSelectStrings("offerings", "organization_name"),
  ]);

  return [...new Set([
    ...staticOrganizations,
    ...authOrganizations,
    ...ecosystemOrganizations,
    ...greSolutionProviderOrganizations,
    ...greSolutionProviderProductOrganizations,
    ...greMisTraderOrganizations,
    ...greMisOfferingOrganizations,
  ])].sort((a, b) => a.localeCompare(b));
}

function getUserUsername(user: Record<string, unknown>) {
  const metadata = getUserMetadata(user);
  return normalizeUsername(String(metadata.username || ""));
}

function getUserOrganization(user: Record<string, unknown>) {
  const metadata = getUserMetadata(user);
  return requireString(metadata.organization);
}

function getUserPrivileges(user: Record<string, unknown>) {
  const appMetadata = getUserAppMetadata(user);
  const privileges = (appMetadata.grameee_privileges || {}) as Record<string, unknown>;
  const role = normalizeRole(requireString(appMetadata.grameee_role));
  const hasGreAccessByRole = ["admin", "moderator", "curator"].includes(role);

  return {
    ecosystem: role === "admin" ? true : privileges.ecosystem !== false,
    askGre: role === "admin" ? true : privileges.askGre !== false,
    offerSolutions: role === "admin" ? true : privileges.offerSolutions !== false,
    askHelp: role === "admin" ? true : privileges.askHelp !== false,
    needsMap: role === "admin" ? true : privileges.needsMap !== false,
    gre: role === "admin" ? true : (typeof privileges.gre === "boolean" ? privileges.gre : hasGreAccessByRole),
  };
}

function getUserRole(user: Record<string, unknown>) {
  const appMetadata = getUserAppMetadata(user);
  return normalizeRole(requireString(appMetadata.grameee_role));
}

function isRemovedUser(user: Record<string, unknown>) {
  const metadata = getUserMetadata(user);
  const appMetadata = getUserAppMetadata(user);
  return metadata.grameee_removed === true || appMetadata.grameee_removed === true;
}

function buildUserSummary(user: Record<string, unknown>) {
  const metadata = getUserMetadata(user);
  return {
    id: String(user.id || ""),
    email: requireString(user.email),
    fullName: requireString(metadata.full_name),
    organization: requireString(metadata.organization),
    organizationLink: requireString(metadata.organization_link),
    phone: requireString(metadata.phone),
    username: requireString(metadata.username),
    role: getUserRole(user),
    privileges: getUserPrivileges(user),
  };
}

async function findUserByLoginId(loginId: string) {
  const normalizedLoginId = normalizeEmail(loginId);
  const normalizedUsername = normalizeUsername(loginId);
  const users = await listAuthUsers();

  return users.find((user) => {
    const email = normalizeEmail(String(user.email || ""));
    const username = getUserUsername(user as Record<string, unknown>);
    return !isRemovedUser(user as Record<string, unknown>) && (email === normalizedLoginId || username === normalizedUsername);
  }) as Record<string, unknown> | undefined;
}

async function isUsernameTaken(username: string, excludeUserId = "") {
  const normalized = normalizeUsername(username);
  const users = await listAuthUsers();

  return users.some((user) => {
    if (excludeUserId && String(user.id) === excludeUserId) {
      return false;
    }

    return getUserUsername(user as Record<string, unknown>) === normalized;
  });
}

async function isEmailTaken(email: string, excludeUserId = "") {
  const normalized = normalizeEmail(email);
  const users = await listAuthUsers();

  return users.some((user) => {
    if (excludeUserId && String(user.id) === excludeUserId) {
      return false;
    }

    return normalizeEmail(String(user.email || "")) === normalized;
  });
}

async function findUserByEmail(email: string) {
  const normalized = normalizeEmail(email);
  const users = await listAuthUsers();

  return users.find((user) => normalizeEmail(String(user.email || "")) === normalized) as Record<string, unknown> | undefined;
}

function isIncompleteUserRecord(user: Record<string, unknown> | undefined) {
  if (!user) {
    return false;
  }

  const metadata = getUserMetadata(user);
  return !requireString(metadata.username) && !requireString(metadata.full_name) && !requireString(metadata.organization);
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

async function verifyAdminAuthUser(authHeader: string) {
  const user = await verifyBearerUser(authHeader);
  const role = normalizeRole(requireString(user.app_metadata?.grameee_role));

  if (role !== "admin") {
    throw new Error("Admin access is required.");
  }

  return user;
}

async function signInWithEmailPassword(email: string, password: string) {
  const response = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: publicAnonKey,
    },
    body: JSON.stringify({
      email,
      password,
    }),
  });

  const data = await response.json().catch(() => null);

  if (!response.ok || !data?.access_token) {
    throw new Error(data?.msg || data?.error_description || data?.error || "Credentials could not be verified.");
  }

  return data;
}

async function handleListOrganizations() {
  const organizations = await loadKnownOrganizations();
  return jsonResponse({ items: organizations });
}

async function handleCheckUsername(username: string, excludeUserId: string) {
  if (!username) {
    return errorResponse("Username is required.", 400);
  }

  const taken = await isUsernameTaken(username, excludeUserId);
  return jsonResponse({ available: !taken });
}

type VerificationTransactionRow = {
  transaction_id: string;
  normalized_target: string;
  purpose: string;
  otp_hash: string;
  expires_at: string;
  attempt_count: number;
  max_attempts: number;
  consumed_at: string | null;
};

const verificationStore = {
  async get(transactionId: string) {
    const { data, error } = await supabase
      .from("grameee_verification_transactions")
      .select("transaction_id, normalized_target, purpose, otp_hash, expires_at, attempt_count, max_attempts, consumed_at")
      .eq("transaction_id", transactionId)
      .maybeSingle();

    if (error) {
      throw new Error("Verification transaction lookup failed.");
    }

    return data ? data as VerificationTransactionRow : null;
  },
  async incrementAttempts(transactionId: string, expectedAttemptCount: number, nowIso: string) {
    const { data, error } = await supabase
      .from("grameee_verification_transactions")
      .update({ attempt_count: expectedAttemptCount + 1 })
      .eq("transaction_id", transactionId)
      .eq("attempt_count", expectedAttemptCount)
      .is("consumed_at", null)
      .gt("expires_at", nowIso)
      .select("transaction_id")
      .maybeSingle();

    if (error) {
      throw new Error("Verification attempt update failed.");
    }

    return Boolean(data?.transaction_id);
  },
  async consume(transactionId: string, expectedAttemptCount: number, nowIso: string) {
    const { data, error } = await supabase
      .from("grameee_verification_transactions")
      .update({ consumed_at: nowIso })
      .eq("transaction_id", transactionId)
      .eq("attempt_count", expectedAttemptCount)
      .is("consumed_at", null)
      .gt("expires_at", nowIso)
      .select("transaction_id")
      .maybeSingle();

    if (error) {
      throw new Error("Verification transaction consumption failed.");
    }

    return Boolean(data?.transaction_id);
  },
  async claim(transactionId: string, target: string, purpose: string, nowIso: string) {
    const { data, error } = await supabase
      .from("grameee_verification_transactions")
      .delete()
      .eq("transaction_id", transactionId)
      .eq("normalized_target", target)
      .eq("purpose", purpose)
      .not("consumed_at", "is", null)
      .gt("expires_at", nowIso)
      .select("transaction_id")
      .maybeSingle();

    if (error) {
      throw new Error("Verification transaction claim failed.");
    }

    return Boolean(data?.transaction_id);
  },
};

function getOriginKeySource(request: Request) {
  return requireString(request.headers.get("cf-connecting-ip"))
    || requireString(request.headers.get("x-forwarded-for")).split(",")[0]?.trim()
    || requireString(request.headers.get("x-real-ip"))
    || "unknown";
}

async function getVerificationRequestMetadata(request: Request) {
  const userAgent = requireString(request.headers.get("user-agent")).slice(0, 512);
  return {
    source: "grameee-auth",
    edge_region: Deno.env.get("SB_REGION") || null,
    user_agent_key: userAgent
      ? await buildRateLimitKey(otpHmacSecret, "user-agent", userAgent)
      : null,
  };
}

const VERIFICATION_FAILURE_MESSAGE = "Verification could not be completed.";
const VERIFICATION_RESEND_COOLDOWN_MS = 60 * 1000;

async function handleSendEmailCode(
  email: string,
  purpose: string,
  request: Request,
  shouldSendEmail = true,
) {
  const normalizedTarget = normalizeVerificationTarget(email);
  const normalizedPurpose = normalizeVerificationPurpose(purpose);

  if (!otpHmacSecret) {
    console.error("OTP HMAC secret is not configured; verification remains unavailable.");
    return errorResponse(VERIFICATION_FAILURE_MESSAGE, 503);
  }

  if (!isValidEmail(normalizedTarget) || !normalizedPurpose) {
    return errorResponse(VERIFICATION_FAILURE_MESSAGE, 400);
  }

  try {
    const material = await createVerificationMaterial({
      secret: otpHmacSecret,
      target: normalizedTarget,
      purpose: normalizedPurpose,
      originKeySource: getOriginKeySource(request),
    });
    const cooldownStartedAt = new Date(Date.now() - VERIFICATION_RESEND_COOLDOWN_MS).toISOString();
    const { data: recentTransaction, error: cooldownError } = await supabase
      .from("grameee_verification_transactions")
      .select("transaction_id")
      .eq("target_rate_limit_key", material.row.target_rate_limit_key)
      .eq("purpose", normalizedPurpose)
      .is("consumed_at", null)
      .gte("created_at", cooldownStartedAt)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (cooldownError) {
      throw new Error("Verification cooldown lookup failed.");
    }

    if (recentTransaction?.transaction_id) {
      return jsonResponse({ transactionId: String(recentTransaction.transaction_id) });
    }

    const { error: insertError } = await supabase
      .from("grameee_verification_transactions")
      .insert({
        ...material.row,
        request_metadata: await getVerificationRequestMetadata(request),
      });

    if (insertError) {
      throw new Error("Verification transaction could not be stored.");
    }

    try {
      if (!shouldSendEmail) {
        return jsonResponse(material.clientResponse);
      }

      await sendMail(
        normalizedTarget,
        normalizedPurpose === "forgot-password" ? "GramEEE password reset code" : "GramEEE email verification code",
        [
          normalizedPurpose === "forgot-password"
            ? "Use this verification code to reset your GramEEE account password."
            : "Use this verification code to verify your GramEEE account email address.",
          "",
          `Verification code: ${material.otp}`,
          "",
          "This code will expire in 10 minutes.",
        ],
      );
    } catch (mailError) {
      await supabase
        .from("grameee_verification_transactions")
        .delete()
        .eq("transaction_id", material.row.transaction_id);
      throw mailError;
    }

    return jsonResponse(material.clientResponse);
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Verification request failed.");
    return errorResponse(VERIFICATION_FAILURE_MESSAGE, 500);
  }
}

async function handleResolveUsername(loginId: string) {
  if (!loginId) {
    return errorResponse("Username or email is required.", 400);
  }

  const user = await findUserByLoginId(loginId);

  if (!user) {
    return errorResponse("No account was found for that login ID.", 404);
  }

  return jsonResponse({
    email: requireString(user.email),
    user: buildUserSummary(user),
  });
}

async function handleVerifyEmailCode(
  email: string,
  transactionId: string,
  verificationCode: string,
  purpose: string,
) {
  if (!otpHmacSecret) {
    console.error("OTP HMAC secret is not configured; verification remains unavailable.");
    return errorResponse(VERIFICATION_FAILURE_MESSAGE, 503);
  }

  try {
    const verified = await verifyVerificationTransaction(
      {
        transactionId,
        target: email,
        purpose,
        otp: verificationCode,
      },
      {
        secret: otpHmacSecret,
        store: verificationStore,
      },
    );

    if (!verified) {
      return errorResponse(VERIFICATION_FAILURE_MESSAGE, 400);
    }

    return jsonResponse({ ok: true, verified: true, transactionId });
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Verification request failed.");
    return errorResponse(VERIFICATION_FAILURE_MESSAGE, 500);
  }
}

async function handleRegisterUser(
  fullName: string,
  organization: string,
  organizationLink: string,
  email: string,
  phone: string,
  username: string,
  password: string,
  transactionId: string,
) {
  if (!fullName || !organization || !email || !username || !password) {
    return errorResponse("Full name, organisation, email, username, and password are required.", 400);
  }

  if (!isValidEmail(email)) {
    return errorResponse("A valid email address is required.", 400);
  }

  if (!isPasswordStrong(password)) {
    return errorResponse("Password must be at least 8 characters with 1 number and 1 special character.", 400);
  }

  const verificationClaimed = await claimConsumedVerification(
    {
      transactionId,
      target: email,
      purpose: "register",
    },
    { store: verificationStore },
  );

  if (!verificationClaimed) {
    return errorResponse(VERIFICATION_FAILURE_MESSAGE, 400);
  }

  if (await isUsernameTaken(username)) {
    return errorResponse("Account could not be created.", 409);
  }

  const existingEmailUser = await findUserByEmail(email);

  if (existingEmailUser && !isIncompleteUserRecord(existingEmailUser)) {
    return errorResponse("Account could not be created.", 409);
  }

  if (existingEmailUser && isIncompleteUserRecord(existingEmailUser)) {
    const { error } = await supabase.auth.admin.updateUserById(String(existingEmailUser.id), {
      password,
      user_metadata: {
        full_name: fullName,
        organization,
        organization_link: organizationLink || null,
        phone: phone || null,
        username: normalizeUsername(username),
      },
      app_metadata: {
        grameee_privileges: privilegeDefaults,
        grameee_role: "user",
      },
    });

    if (error) {
      return errorResponse("Account could not be created.", 500);
    }

    const refreshed = await supabase.auth.admin.getUserById(String(existingEmailUser.id));

    return jsonResponse({
      ok: true,
      repairedExistingAccount: true,
      user: buildUserSummary({
        id: refreshed.data.user?.id || String(existingEmailUser.id),
        email: refreshed.data.user?.email || normalizeEmail(email),
        raw_user_meta_data: refreshed.data.user?.user_metadata || {
          full_name: fullName,
          organization,
          organization_link: organizationLink || null,
          phone: phone || null,
          username: normalizeUsername(username),
        },
        raw_app_meta_data: refreshed.data.user?.app_metadata || {
          grameee_privileges: privilegeDefaults,
          grameee_role: "user",
        },
      }),
    });
  }

  const { data, error } = await supabase.auth.admin.createUser({
    email: normalizeEmail(email),
    password,
    email_confirm: true,
    user_metadata: {
      full_name: fullName,
      organization,
      organization_link: organizationLink || null,
      phone: phone || null,
      username: normalizeUsername(username),
    },
    app_metadata: {
      grameee_privileges: privilegeDefaults,
      grameee_role: "user",
    },
  });

  if (error || !data.user) {
    return errorResponse("Account could not be created.", 500);
  }

  const refreshed = await supabase.auth.admin.getUserById(data.user.id);
  const refreshedUser = refreshed.data.user;

  return jsonResponse({
    ok: true,
    user: buildUserSummary({
      id: refreshedUser?.id || data.user.id,
      email: refreshedUser?.email || data.user.email,
      raw_user_meta_data: refreshedUser?.user_metadata || data.user.user_metadata,
      raw_app_meta_data: refreshedUser?.app_metadata || data.user.app_metadata,
    }),
  });
}

async function handleForgotPasswordStart(loginId: string, request: Request) {
  const startedAt = Date.now();
  const user = await findUserByLoginId(loginId);
  const userEmail = normalizeEmail(String(user?.email || ""));
  const hasDeliverableAccount = Boolean(user && isValidEmail(userEmail));
  const target = hasDeliverableAccount
    ? userEmail
    : await buildRecoveryDecoyTarget(otpHmacSecret, loginId);

  const response = await handleSendEmailCode(
    target,
    "forgot-password",
    request,
    hasDeliverableAccount,
  );
  const minimumResponseTimeMs = 1200;
  const remainingDelayMs = minimumResponseTimeMs - (Date.now() - startedAt);

  if (remainingDelayMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, remainingDelayMs));
  }

  return response;
}

async function handleForgotPasswordComplete(
  loginId: string,
  newPassword: string,
  transactionId: string,
  verificationCode: string,
  request: Request,
) {
  if (!isPasswordStrong(newPassword)) {
    return errorResponse("Password must be at least 8 characters with 1 number and 1 special character.", 400);
  }

  const user = await findUserByLoginId(loginId);
  const userEmail = normalizeEmail(String(user?.email || ""));
  const hasDeliverableAccount = Boolean(user && isValidEmail(userEmail));
  const target = hasDeliverableAccount
    ? userEmail
    : await buildRecoveryDecoyTarget(otpHmacSecret, loginId);

  try {
    const verified = await verifyVerificationTransaction(
      {
        transactionId,
        target,
        purpose: "forgot-password",
        otp: verificationCode,
      },
      {
        secret: otpHmacSecret,
        store: verificationStore,
      },
    );

    if (!verified || !hasDeliverableAccount || !user) {
      return errorResponse(VERIFICATION_FAILURE_MESSAGE, 400);
    }

    const verificationClaimed = await claimConsumedVerification(
      {
        transactionId,
        target,
        purpose: "forgot-password",
      },
      { store: verificationStore },
    );

    if (!verificationClaimed) {
      return errorResponse(VERIFICATION_FAILURE_MESSAGE, 400);
    }

    await completePasswordResetSecurity(
      {
        userId: String(user.id),
        userEmail,
        newPassword,
        requestMetadata: await getVerificationRequestMetadata(request),
      },
      {
        revokeSessions: async (userId: string) => {
          const { data, error } = await supabase.rpc("grameee_revoke_user_sessions", {
            p_user_id: userId,
          });
          if (error) {
            throw new Error("Existing sessions could not be revoked.");
          }
          const revokedCount = Number(data);
          return Number.isSafeInteger(revokedCount) && revokedCount >= 0 ? revokedCount : 0;
        },
        updatePassword: async (userId: string, password: string) => {
          const { error } = await supabase.auth.admin.updateUserById(userId, { password });
          if (error) {
            throw new Error("Password could not be updated.");
          }
        },
        sendNotification: async (email: string, bodyLines: string[]) => {
          await sendMail(email, "Your GramEEE password was reset", bodyLines);
        },
        writeAudit: async (event: Record<string, unknown>) => {
          const { error } = await supabase
            .from("grameee_security_audit_events")
            .insert(event);
          if (error) {
            throw new Error("Password-reset audit event could not be recorded.");
          }
        },
        onOperationalError: (message: string) => console.error(message),
      },
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Password recovery failed.");
    return errorResponse(VERIFICATION_FAILURE_MESSAGE, 500);
  }

  return jsonResponse({ ok: true });
}

async function handleUserChangePassword(loginId: string, currentPassword: string, newPassword: string) {
  if (!loginId || !currentPassword || !newPassword) {
    return errorResponse("Login ID, current password, and new password are required.", 400);
  }

  if (!isPasswordStrong(newPassword)) {
    return errorResponse("Password must be at least 8 characters with 1 number and 1 special character.", 400);
  }

  const user = await findUserByLoginId(loginId);

  if (!user) {
    return errorResponse("No account was found for that login ID.", 404);
  }

  try {
    await signInWithEmailPassword(String(user.email || ""), currentPassword);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Current credentials are incorrect.";
    return errorResponse(message, 401);
  }

  const { error } = await supabase.auth.admin.updateUserById(String(user.id), {
    password: newPassword,
  });

  if (error) {
    return errorResponse(error.message || "Password could not be updated.", 500);
  }

  const userUsername = getUserUsername(user as Record<string, unknown>).toLowerCase();
  if (userUsername === "admin") {
    const { data: passwordHash, error: hashError } = await supabase.rpc("grameee_hash_admin_password", {
      p_password: newPassword,
    });

    if (!hashError && passwordHash && typeof passwordHash === "string") {
      await supabase.from("grameee_admin_accounts").upsert(
        { username: "admin", password_hash: passwordHash, updated_at: new Date().toISOString() },
        { onConflict: "username" }
      );
    }
  }

  return jsonResponse({ ok: true });
}

async function handleGetProfile(authHeader: string) {
  const user = await verifyBearerUser(authHeader);
  return jsonResponse({
    user: {
      id: user.id,
      email: user.email ?? "",
      fullName: requireString(user.user_metadata?.full_name),
      organization: requireString(user.user_metadata?.organization),
      organizationLink: requireString(user.user_metadata?.organization_link),
      phone: requireString(user.user_metadata?.phone),
      username: requireString(user.user_metadata?.username),
      role: normalizeRole(requireString(user.app_metadata?.grameee_role)),
      privileges: getUserPrivileges(user as Record<string, unknown>),
    },
  });
}

async function handleUpdateProfile(
  authHeader: string,
  fullName: string,
  organization: string,
  organizationLink: string,
  email: string,
  phone: string,
  username: string,
) {
  const currentUser = await verifyBearerUser(authHeader);

  if (!fullName || !organization || !email || !username) {
    return errorResponse("Full name, organisation, email, and username are required.", 400);
  }

  if (!isValidEmail(email)) {
    return errorResponse("A valid email address is required.", 400);
  }

  if (await isUsernameTaken(username, currentUser.id)) {
    return errorResponse("That username is already in use.", 409);
  }

  if (await isEmailTaken(email, currentUser.id)) {
    return errorResponse("That email address already has an account.", 409);
  }

  const { error } = await supabase.auth.admin.updateUserById(currentUser.id, {
    email: normalizeEmail(email),
    user_metadata: {
      ...currentUser.user_metadata,
      full_name: fullName,
      organization,
      organization_link: organizationLink || null,
      phone: phone || null,
      username: normalizeUsername(username),
    },
  });

  if (error) {
    return errorResponse(error.message || "Profile could not be updated.", 500);
  }

  const refreshed = await supabase.auth.admin.getUserById(currentUser.id);

  return jsonResponse({
    ok: true,
    user: {
      id: refreshed.data.user?.id || currentUser.id,
      email: refreshed.data.user?.email || normalizeEmail(email),
      fullName,
      organization,
      organizationLink: organizationLink || "",
      phone: phone || "",
      username: normalizeUsername(username),
      role: normalizeRole(requireString(refreshed.data.user?.app_metadata?.grameee_role || currentUser.app_metadata?.grameee_role)),
      privileges: getUserPrivileges((refreshed.data.user || currentUser) as Record<string, unknown>),
    },
  });
}

async function handleDeleteProfile(authHeader: string) {
  const currentUser = await verifyBearerUser(authHeader);
  const currentMetadata = (currentUser.user_metadata || {}) as Record<string, unknown>;
  const currentAppMetadata = (currentUser.app_metadata || {}) as Record<string, unknown>;

  const randomPassword = `${crypto.randomUUID()}!9A`;
  const { error } = await supabase.auth.admin.updateUserById(currentUser.id, {
    password: randomPassword,
    user_metadata: {
      ...currentMetadata,
      grameee_removed: true,
      grameee_removed_at: new Date().toISOString(),
    },
    app_metadata: {
      ...currentAppMetadata,
      grameee_removed: true,
      grameee_role: "removed",
    },
  });

  if (error) {
    return errorResponse(error.message || "User record could not be removed.", 500);
  }

  return jsonResponse({
    ok: true,
    removed: true,
  });
}

async function handleAdminBridgeSync(password: string) {
  if (!password) {
    return errorResponse("Admin password is required.", 400);
  }

  const { data: matches, error: passwordError } = await supabase.rpc("grameee_admin_password_matches", {
    p_username: "admin",
    p_password: password,
  });

  if (passwordError) {
    return errorResponse(`Admin password verification failed: ${passwordError.message}`, 500);
  }

  if (!matches) {
    return errorResponse("Invalid admin password.", 401);
  }

  const adminEmail = "tanmay@greenruraleconomy.in";
  const existingAdminUser = await findUserByEmail(adminEmail);
  const userMetadata = {
    full_name: "GramEEE Admin",
    organization: "Green Rural Economy",
    organization_link: "",
    phone: "",
    username: "admin",
  };

  if (existingAdminUser) {
    const existingAppMetadata = getUserAppMetadata(existingAdminUser);
    const appMetadata = {
      ...existingAppMetadata,
      grameee_privileges: {
        ...privilegeDefaults,
        ...(existingAppMetadata.grameee_privileges && typeof existingAppMetadata.grameee_privileges === "object"
          ? existingAppMetadata.grameee_privileges as Record<string, unknown>
          : {}),
        gre: true,
      },
      grameee_role: "admin",
    };
    const { error } = await supabase.auth.admin.updateUserById(String(existingAdminUser.id), {
      password,
      email: adminEmail,
      user_metadata: userMetadata,
      app_metadata: appMetadata,
      email_confirm: true,
    });

    if (error) {
      return errorResponse(error.message || "Admin bridge user could not be updated.", 500);
    }

    const refreshed = await supabase.auth.admin.getUserById(String(existingAdminUser.id));
    const session = await signInWithEmailPassword(adminEmail, password);
    return jsonResponse({
      ok: true,
      email: adminEmail,
      session: {
        access_token: String(session.access_token || ""),
        refresh_token: String(session.refresh_token || ""),
        expires_in: Number(session.expires_in || 0),
        expires_at: Number(session.expires_at || 0),
        token_type: String(session.token_type || "bearer"),
      },
      user: buildUserSummary({
        id: refreshed.data.user?.id || String(existingAdminUser.id),
        email: refreshed.data.user?.email || adminEmail,
        user_metadata: refreshed.data.user?.user_metadata || userMetadata,
        app_metadata: refreshed.data.user?.app_metadata || appMetadata,
      }),
    });
  }

  const appMetadata = {
    grameee_privileges: {
      ...privilegeDefaults,
      gre: true,
    },
    grameee_role: "admin",
  };
  const { data, error } = await supabase.auth.admin.createUser({
    email: adminEmail,
    password,
    email_confirm: true,
    user_metadata: userMetadata,
    app_metadata: appMetadata,
  });

  if (error || !data.user) {
    return errorResponse(error?.message || "Admin bridge user could not be created.", 500);
  }

  const session = await signInWithEmailPassword(adminEmail, password);

  return jsonResponse({
    ok: true,
    email: adminEmail,
    session: {
      access_token: String(session.access_token || ""),
      refresh_token: String(session.refresh_token || ""),
      expires_in: Number(session.expires_in || 0),
      expires_at: Number(session.expires_at || 0),
      token_type: String(session.token_type || "bearer"),
    },
    user: buildUserSummary({
      id: data.user.id,
      email: data.user.email || adminEmail,
      user_metadata: data.user.user_metadata || userMetadata,
      app_metadata: data.user.app_metadata || appMetadata,
    }),
  });
}

async function handleAdminListUsers(authHeader: string) {
  await verifyAdminAuthUser(authHeader);
  const users = await listAuthUsers();
  const { data: membershipRows, error: membershipsError } = await supabase
    .from("gre_mis_organisation_memberships")
    .select("id,organisation_id,user_email,role,status,organisation:gre_mis_organisations(id,name,normalized_name)");
  if (membershipsError) {
    return errorResponse("Organisation roles could not be loaded.", 500);
  }

  const visibleUsers = users
    .filter((user) => !isRemovedUser(user as Record<string, unknown>))
    .map((user) => {
      const summary = buildUserSummary(user as Record<string, unknown>);
      const normalizedEmail = normalizeEmail(summary.email);
      const normalizedOrganisation = normalizeOrganisationName(summary.organization);
      const userMemberships = (membershipRows || []).filter((row) => normalizeEmail(requireString(row.user_email)) === normalizedEmail);
      const primaryMembership = userMemberships.find((row) => {
        const organisation = Array.isArray(row.organisation) ? row.organisation[0] : row.organisation;
        const organisationRecord = (organisation && typeof organisation === "object" ? organisation : {}) as Record<string, unknown>;
        return normalizeOrganisationName(requireString(organisationRecord.normalized_name || organisationRecord.name)) === normalizedOrganisation;
      });
      return {
        ...summary,
        organisationRole: requireString(primaryMembership?.role),
        organisationRoleStatus: requireString(primaryMembership?.status),
        organisationMembershipId: requireString(primaryMembership?.id),
      };
    })
    .sort((a, b) => a.username.localeCompare(b.username));

  return jsonResponse({ items: visibleUsers });
}

async function updateUserOrganisationRole(input: {
  userId: string;
  previousEmail: string;
  email: string;
  organisation: string;
  organisationRole: string;
  adminUserId: string;
}) {
  const requestedRole = requireString(input.organisationRole).toLowerCase();
  if (requestedRole && !(organisationRoleLabels as readonly string[]).includes(requestedRole)) {
    throw new Error("Invalid organisation role.");
  }

  const normalizedOrganisation = normalizeOrganisationName(input.organisation);
  if (!normalizedOrganisation) {
    if (requestedRole) throw new Error("Organisation is required before assigning an organisation role.");
    return;
  }

  let { data: organisation, error: organisationError } = await supabase
    .from("gre_mis_organisations")
    .select("id,name,normalized_name")
    .eq("normalized_name", normalizedOrganisation)
    .maybeSingle();
  if (organisationError) throw new Error(organisationError.message);

  if (!organisation && requestedRole) {
    const created = await supabase
      .from("gre_mis_organisations")
      .insert({
        name: input.organisation.trim(),
        normalized_name: normalizedOrganisation,
        source: "grameee_admin",
      })
      .select("id,name,normalized_name")
      .single();
    if (created.error || !created.data) throw new Error(created.error?.message || "Organisation could not be created.");
    organisation = created.data;
  }

  if (!organisation?.id) return;

  const normalizedEmail = normalizeEmail(input.email);
  const previousEmail = normalizeEmail(input.previousEmail);
  let { data: existing, error: existingError } = await supabase
    .from("gre_mis_organisation_memberships")
    .select("id,role,status,user_email,user_id")
    .eq("organisation_id", organisation.id)
    .eq("user_email", normalizedEmail)
    .maybeSingle();
  if (existingError) throw new Error(existingError.message);

  if (!existing && previousEmail && previousEmail !== normalizedEmail) {
    const previousMembership = await supabase
      .from("gre_mis_organisation_memberships")
      .select("id,role,status,user_email,user_id")
      .eq("organisation_id", organisation.id)
      .eq("user_email", previousEmail)
      .maybeSingle();
    if (previousMembership.error) throw new Error(previousMembership.error.message);
    existing = previousMembership.data;
  }

  const isDowngradingLastAdmin = existing?.role === "org_admin" && existing?.status === "approved" && requestedRole !== "org_admin";
  if (isDowngradingLastAdmin) {
    const { count, error } = await supabase
      .from("gre_mis_organisation_memberships")
      .select("id", { count: "exact", head: true })
      .eq("organisation_id", organisation.id)
      .eq("role", "org_admin")
      .eq("status", "approved");
    if (error) throw new Error(error.message);
    if ((count || 0) <= 1) throw new Error("At least one approved organisation admin is required.");
  }

  if (!requestedRole) {
    if (!existing?.id) return;
    const { error } = await supabase
      .from("gre_mis_organisation_memberships")
      .update({ status: "revoked", approved_at: new Date().toISOString() })
      .eq("id", existing.id);
    if (error) throw new Error(error.message);
    return;
  }

  const membershipRow = {
    organisation_id: organisation.id,
    user_email: normalizedEmail,
    role: requestedRole as OrganisationRole,
    status: "approved",
    approved_at: new Date().toISOString(),
    notes: `Assigned by GramEEE admin ${input.adminUserId}.`,
  };

  const membershipResult = existing?.id
    ? await supabase.from("gre_mis_organisation_memberships").update(membershipRow).eq("id", existing.id)
    : await supabase.from("gre_mis_organisation_memberships").insert(membershipRow);
  if (membershipResult.error) throw new Error(membershipResult.error.message);
}

async function handleAdminUpdateUser(
  authHeader: string,
  userId: string,
  fullName: string,
  organization: string,
  organizationLink: string,
  email: string,
  phone: string,
  username: string,
  role: string,
  organisationRole: string,
) {
  const adminUser = await verifyAdminAuthUser(authHeader);

  if (!userId || !fullName || !organization || !email || !username) {
    return errorResponse("User ID, full name, organisation, email, and username are required.", 400);
  }

  if (!isValidEmail(email)) {
    return errorResponse("A valid email address is required.", 400);
  }

  const users = await listAuthUsers();
  const target = users.find((item) => String(item.id) === userId) as Record<string, unknown> | undefined;

  if (!target || isRemovedUser(target)) {
    return errorResponse("The selected user could not be found.", 404);
  }

  if (await isUsernameTaken(username, userId)) {
    return errorResponse("That username is already in use.", 409);
  }

  if (await isEmailTaken(email, userId)) {
    return errorResponse("That email address already has an account.", 409);
  }

  const targetRole = normalizeRole(role);
  const targetAppMetadata = getUserAppMetadata(target);

  if (normalizeUsername(username) === "admin" && targetRole !== "admin") {
    return errorResponse("The admin username must retain the admin role.", 400);
  }

  const { error } = await supabase.auth.admin.updateUserById(userId, {
    email: normalizeEmail(email),
    user_metadata: {
      ...getUserMetadata(target),
      full_name: fullName,
      organization,
      organization_link: organizationLink || null,
      phone: phone || null,
      username: normalizeUsername(username),
    },
    app_metadata: {
      ...targetAppMetadata,
      grameee_privileges: {
        ...privilegeDefaults,
        ...(targetAppMetadata.grameee_privileges || {}),
      },
      grameee_role: targetRole,
      updated_by_admin_id: adminUser.id,
    },
  });

  if (error) {
    return errorResponse(error.message || "User details could not be updated.", 500);
  }

  try {
    await updateUserOrganisationRole({
      userId,
      previousEmail: requireString(target.email),
      email,
      organisation: organization,
      organisationRole,
      adminUserId: String(adminUser.id),
    });
  } catch (organisationRoleError) {
    return errorResponse(
      organisationRoleError instanceof Error ? organisationRoleError.message : "Organisation role could not be updated.",
      500,
    );
  }

  const refreshed = await supabase.auth.admin.getUserById(userId);
  return jsonResponse({
    ok: true,
    user: buildUserSummary({
      id: refreshed.data.user?.id || userId,
      email: refreshed.data.user?.email || normalizeEmail(email),
      user_metadata: refreshed.data.user?.user_metadata || {
        full_name: fullName,
        organization,
        organization_link: organizationLink || null,
        phone: phone || null,
        username: normalizeUsername(username),
      },
      app_metadata: refreshed.data.user?.app_metadata || {
        ...targetAppMetadata,
        grameee_privileges: privilegeDefaults,
        grameee_role: targetRole,
      },
    }),
  });
}

async function handleAdminDeleteUser(authHeader: string, userId: string) {
  await verifyAdminAuthUser(authHeader);

  if (!userId) {
    return errorResponse("User ID is required.", 400);
  }

  const users = await listAuthUsers();
  const target = users.find((item) => String(item.id) === userId) as Record<string, unknown> | undefined;

  if (!target || isRemovedUser(target)) {
    return errorResponse("The selected user could not be found.", 404);
  }

  if (getUserUsername(target) === "admin") {
    return errorResponse("The admin account cannot be removed from this screen.", 400);
  }

  const randomPassword = `${crypto.randomUUID()}!9A`;
  const { error } = await supabase.auth.admin.updateUserById(userId, {
    password: randomPassword,
    user_metadata: {
      ...getUserMetadata(target),
      grameee_removed: true,
      grameee_removed_at: new Date().toISOString(),
    },
    app_metadata: {
      ...getUserAppMetadata(target),
      grameee_removed: true,
      grameee_role: "user",
    },
  });

  if (error) {
    return errorResponse(error.message || "User record could not be removed.", 500);
  }

  return jsonResponse({ ok: true, removed: true });
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
  const fullName = requireString(body.fullName);
  const organization = requireString(body.organization);
  const organizationLink = requireString(body.organizationLink);
  const email = requireString(body.email);
  const phone = requireString(body.phone);
  const username = requireString(body.username);
  const role = requireString(body.role);
  const organisationRole = requireString(body.organisationRole || body.organizationRole);
  const password = requireString(body.password);
  const loginId = requireString(body.loginId);
  const userId = requireString(body.userId);
  const purpose = requireString(body.purpose);
  const transactionId = requireString(body.transactionId);
  const verificationCode = requireString(body.verificationCode);
  const currentPassword = requireString(body.currentPassword);
  const newPassword = requireString(body.newPassword);
  const excludeUserId = requireString(body.excludeUserId);
  const authHeader = request.headers.get("Authorization") || "";

  try {
    if (AUTH_VERIFICATION_ACTIONS.has(action) && !(await isSecurityFlagEnabled(AUTH_VERIFICATION_FLAG))) {
      return errorResponse(AUTH_VERIFICATION_MAINTENANCE_MESSAGE, 503);
    }

    switch (action) {
      case "listOrganizations":
        return await handleListOrganizations();
      case "checkUsername":
        return await handleCheckUsername(username, excludeUserId);
      case "sendEmailCode":
        return await handleSendEmailCode(email, purpose || "register", request);
      case "resolveUsername":
        return await handleResolveUsername(loginId || username || email);
      case "adminBridgeSync":
        return await handleAdminBridgeSync(password);
      case "verifyEmailCode":
        return await handleVerifyEmailCode(email, transactionId, verificationCode, purpose || "register");
      case "registerUser":
        return await handleRegisterUser(
          fullName,
          organization,
          organizationLink,
          email,
          phone,
          username,
          password,
          transactionId,
        );
      case "forgotPasswordStart":
        return await handleForgotPasswordStart(loginId || username || email, request);
      case "forgotPasswordComplete":
        return await handleForgotPasswordComplete(
          loginId || username || email,
          newPassword,
          transactionId,
          verificationCode,
          request,
        );
      case "changePassword":
        return await handleUserChangePassword(loginId || username || email, currentPassword, newPassword);
      case "getProfile":
        return await handleGetProfile(authHeader);
      case "updateProfile":
        return await handleUpdateProfile(authHeader, fullName, organization, organizationLink, email, phone, username);
      case "deleteProfile":
        return await handleDeleteProfile(authHeader);
      case "adminListUsers":
        return await handleAdminListUsers(authHeader);
      case "adminUpdateUser":
        return await handleAdminUpdateUser(authHeader, userId, fullName, organization, organizationLink, email, phone, username, role, organisationRole);
      case "adminDeleteUser":
        return await handleAdminDeleteUser(authHeader, userId);
      default:
        return errorResponse("Unknown auth action.", 400);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : "Auth request failed.";
    return errorResponse(message, 500);
  }
});
