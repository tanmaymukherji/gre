import { createClient } from "npm:@supabase/supabase-js@2";

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
const codeSigningSecret = Deno.env.get("GRAMEEE_AUTH_CODE_SECRET") || serviceRoleKey;
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

function makeSixDigitCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function toBase64Url(input: string) {
  return btoa(input)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(input: string) {
  const normalized = input
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(input.length / 4) * 4, "=");

  return atob(normalized);
}

async function sha256Hex(input: string) {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function signPayload(payload: Record<string, unknown>) {
  const encoded = toBase64Url(JSON.stringify(payload));
  const signature = await sha256Hex(`${encoded}.${codeSigningSecret}`);
  return `${encoded}.${signature}`;
}

async function verifySignedPayload(token: string) {
  const [encoded, signature] = token.split(".");

  if (!encoded || !signature) {
    throw new Error("Verification token is invalid.");
  }

  const expectedSignature = await sha256Hex(`${encoded}.${codeSigningSecret}`);

  if (expectedSignature !== signature) {
    throw new Error("Verification token is invalid.");
  }

  const payload = JSON.parse(fromBase64Url(encoded));

  if (!payload?.exp || Number(payload.exp) < Date.now()) {
    throw new Error("Verification token has expired.");
  }

  return payload as Record<string, unknown>;
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

async function handleSendEmailCode(email: string, purpose: string) {
  if (!isValidEmail(email)) {
    return errorResponse("A valid email address is required.", 400);
  }

  const code = makeSixDigitCode();
  const token = await signPayload({
    email: normalizeEmail(email),
    code,
    purpose,
    exp: Date.now() + 15 * 60 * 1000,
  });

  await sendMail(
    normalizeEmail(email),
    purpose === "forgot-password" ? "GramEEE password reset code" : "GramEEE email verification code",
    [
      purpose === "forgot-password"
        ? "Use this verification code to reset your GramEEE account password."
        : "Use this verification code to verify your GramEEE account email address.",
      "",
      `Verification code: ${code}`,
      "",
      "This code will expire in 15 minutes.",
    ],
  );

  return jsonResponse({ token });
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

async function handleVerifyEmailCode(email: string, verificationToken: string, verificationCode: string, purpose: string) {
  if (!email || !verificationToken || !verificationCode) {
    return errorResponse("Email, verification token, and verification code are required.", 400);
  }

  const payload = await verifySignedPayload(verificationToken);

  if ((purpose || "register") !== String(payload.purpose || "")) {
    return errorResponse("Verification purpose does not match.", 400);
  }

  if (normalizeEmail(String(payload.email || "")) !== normalizeEmail(email)) {
    return errorResponse("Verification email does not match.", 400);
  }

  if (String(payload.code || "") !== verificationCode) {
    return errorResponse("Verification code is incorrect.", 400);
  }

  return jsonResponse({
    ok: true,
    verified: true,
    email: normalizeEmail(email),
    purpose: String(payload.purpose || purpose || "register"),
  });
}

async function handleRegisterUser(
  fullName: string,
  organization: string,
  organizationLink: string,
  email: string,
  phone: string,
  username: string,
  password: string,
  verificationToken: string,
  verificationCode: string,
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

  const payload = await verifySignedPayload(verificationToken);

  if (payload.purpose !== "register" || normalizeEmail(String(payload.email || "")) !== normalizeEmail(email)) {
    return errorResponse("Email verification does not match this account request.", 400);
  }

  if (String(payload.code || "") !== verificationCode) {
    return errorResponse("Verification code is incorrect.", 400);
  }

  if (await isUsernameTaken(username)) {
    return errorResponse("That username is already in use.", 409);
  }

  const existingEmailUser = await findUserByEmail(email);

  if (existingEmailUser && !isIncompleteUserRecord(existingEmailUser)) {
    return errorResponse("That email address already has an account.", 409);
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
      return errorResponse(error.message || "Existing account could not be completed.", 500);
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
    return errorResponse(error?.message || "Account could not be created.", 500);
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

async function handleForgotPasswordStart(loginId: string) {
  const user = await findUserByLoginId(loginId);

  if (!user) {
    return errorResponse("No account was found for that login ID.", 404);
  }

  return await handleSendEmailCode(String(user.email || ""), "forgot-password");
}

async function handleForgotPasswordComplete(
  loginId: string,
  newPassword: string,
  verificationToken: string,
  verificationCode: string,
) {
  if (!isPasswordStrong(newPassword)) {
    return errorResponse("Password must be at least 8 characters with 1 number and 1 special character.", 400);
  }

  const user = await findUserByLoginId(loginId);

  if (!user) {
    return errorResponse("No account was found for that login ID.", 404);
  }

  const payload = await verifySignedPayload(verificationToken);
  const userEmail = normalizeEmail(String(user.email || ""));

  if (payload.purpose !== "forgot-password" || normalizeEmail(String(payload.email || "")) !== userEmail) {
    return errorResponse("Password reset verification does not match this account.", 400);
  }

  if (String(payload.code || "") !== verificationCode) {
    return errorResponse("Verification code is incorrect.", 400);
  }

  const { error } = await supabase.auth.admin.updateUserById(String(user.id), {
    password: newPassword,
  });

  if (error) {
    return errorResponse(error.message || "Password could not be updated.", 500);
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
  const visibleUsers = users
    .filter((user) => !isRemovedUser(user as Record<string, unknown>))
    .map((user) => buildUserSummary(user as Record<string, unknown>))
    .sort((a, b) => a.username.localeCompare(b.username));

  return jsonResponse({ items: visibleUsers });
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

  if (!supabaseUrl || !serviceRoleKey || !codeSigningSecret) {
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
  const password = requireString(body.password);
  const loginId = requireString(body.loginId);
  const userId = requireString(body.userId);
  const purpose = requireString(body.purpose);
  const verificationToken = requireString(body.verificationToken);
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
        return await handleSendEmailCode(email, purpose || "register");
      case "resolveUsername":
        return await handleResolveUsername(loginId || username || email);
      case "adminBridgeSync":
        return await handleAdminBridgeSync(password);
      case "verifyEmailCode":
        return await handleVerifyEmailCode(email, verificationToken, verificationCode, purpose || "register");
      case "registerUser":
        return await handleRegisterUser(
          fullName,
          organization,
          organizationLink,
          email,
          phone,
          username,
          password,
          verificationToken,
          verificationCode,
        );
      case "forgotPasswordStart":
        return await handleForgotPasswordStart(loginId || username || email);
      case "forgotPasswordComplete":
        return await handleForgotPasswordComplete(loginId || username || email, newPassword, verificationToken, verificationCode);
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
        return await handleAdminUpdateUser(authHeader, userId, fullName, organization, organizationLink, email, phone, username, role);
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
