export const EXCHANGE_TTL_MS = 60_000;
export const STANDARD_IDLE_MS = 24 * 60 * 60 * 1000;
export const STANDARD_ABSOLUTE_MS = 7 * 24 * 60 * 60 * 1000;
export const PRIVILEGED_IDLE_MS = 30 * 60 * 1000;
export const PRIVILEGED_ABSOLUTE_MS = 8 * 60 * 60 * 1000;

const CLIENT_ID_PATTERN = /^[a-z][a-z0-9_-]{2,63}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/;
const ROLE_VALUES = new Set(["admin", "moderator", "curator", "user"]);

function requireCrypto(cryptoProvider) {
  if (!cryptoProvider?.getRandomValues || !cryptoProvider?.subtle) {
    throw new Error("Secure Web Crypto is unavailable.");
  }
  return cryptoProvider;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((value) => value.toString(16).padStart(2, "0")).join("");
}

function base64Url(bytes) {
  let binary = "";
  for (const value of bytes) binary += String.fromCharCode(value);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function importHmacKey(secret, cryptoProvider) {
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error("Session exchange HMAC secret is not configured securely.");
  }
  return await cryptoProvider.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export function normalizeClientId(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return CLIENT_ID_PATTERN.test(normalized) ? normalized : "";
}

export function normalizeRole(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return ROLE_VALUES.has(normalized) ? normalized : "user";
}

export function normalizePrivileges(value, roleInput = "user") {
  const privileges = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const role = normalizeRole(roleInput);
  const administrator = role === "admin";
  return {
    ecosystem: administrator || privileges.ecosystem !== false,
    askGre: administrator || privileges.askGre !== false,
    offerSolutions: administrator || privileges.offerSolutions !== false,
    askHelp: administrator || privileges.askHelp !== false,
    needsMap: administrator || privileges.needsMap !== false,
    gre: administrator || (typeof privileges.gre === "boolean"
      ? privileges.gre
      : role === "moderator" || role === "curator"),
  };
}

export function isExactRedirectAllowed(value, registered) {
  if (typeof value !== "string" || !Array.isArray(registered) || !registered.includes(value)) return false;
  try {
    const url = new URL(value);
    return url.protocol === "https:"
      && !url.username
      && !url.password
      && !url.hash
      && url.origin !== "null"
      && url.toString() === value;
  } catch {
    return false;
  }
}

export function isExchangeToken(value) {
  return typeof value === "string" && TOKEN_PATTERN.test(value);
}

export function isPkceVerifier(value) {
  return typeof value === "string" && VERIFIER_PATTERN.test(value);
}

export function generateOpaqueToken(cryptoProvider = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoProvider);
  const bytes = new Uint8Array(32);
  safeCrypto.getRandomValues(bytes);
  return base64Url(bytes);
}

export async function sha256Base64Url(value, cryptoProvider = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoProvider);
  const digest = await safeCrypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value)));
  return base64Url(new Uint8Array(digest));
}

export async function keyedHash(secret, purpose, parts, cryptoProvider = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoProvider);
  const key = await importHmacKey(secret, safeCrypto);
  const message = ["grameee-session-exchange-v1", purpose, ...parts.map(String)].join("\u0000");
  const signature = await safeCrypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(signature));
}

export async function hashClientSecret(secret, clientId, clientSecret, cryptoProvider = globalThis.crypto) {
  return await keyedHash(secret, "client-secret", [normalizeClientId(clientId), clientSecret], cryptoProvider);
}

export async function verifyClientSecret(secret, clientId, clientSecret, expectedHash, cryptoProvider = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoProvider);
  if (typeof clientSecret !== "string" || clientSecret.length < 32 || clientSecret.length > 256 || !/^[0-9a-f]{64}$/i.test(expectedHash || "")) {
    await keyedHash(secret, "client-secret", [normalizeClientId(clientId), String(clientSecret || "").slice(0, 256)], safeCrypto);
    return false;
  }
  const key = await importHmacKey(secret, safeCrypto);
  const message = ["grameee-session-exchange-v1", "client-secret", normalizeClientId(clientId), clientSecret].join("\u0000");
  const expected = Uint8Array.from(expectedHash.match(/.{2}/g).map((pair) => Number.parseInt(pair, 16)));
  return await safeCrypto.subtle.verify("HMAC", key, expected, new TextEncoder().encode(message));
}

export async function issueMaterial({ secret, userId, sessionId, clientId, audience, redirectUri, pkceChallenge, contextSource, now = Date.now() }, cryptoProvider = globalThis.crypto) {
  const code = generateOpaqueToken(cryptoProvider);
  return {
    code,
    row: {
      code_hash: await keyedHash(secret, "exchange-code", [code], cryptoProvider),
      user_id: userId,
      source_session_id: sessionId,
      client_id: normalizeClientId(clientId),
      audience,
      redirect_uri: redirectUri,
      pkce_challenge: pkceChallenge,
      issued_at: new Date(now).toISOString(),
      expires_at: new Date(now + EXCHANGE_TTL_MS).toISOString(),
      issue_context_hash: await keyedHash(secret, "request-context", [contextSource], cryptoProvider),
    },
  };
}

export async function sessionMaterial({ secret, role, now = Date.now() }, cryptoProvider = globalThis.crypto) {
  const sessionToken = generateOpaqueToken(cryptoProvider);
  const privileged = normalizeRole(role) === "admin";
  const idleMs = privileged ? PRIVILEGED_IDLE_MS : STANDARD_IDLE_MS;
  const absoluteMs = privileged ? PRIVILEGED_ABSOLUTE_MS : STANDARD_ABSOLUTE_MS;
  return {
    sessionToken,
    sessionTokenHash: await keyedHash(secret, "application-session", [sessionToken], cryptoProvider),
    idleExpiresAt: new Date(now + idleMs).toISOString(),
    absoluteExpiresAt: new Date(now + absoluteMs).toISOString(),
  };
}
