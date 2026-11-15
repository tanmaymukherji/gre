export const VERIFICATION_TTL_MS = 10 * 60 * 1000;
export const VERIFICATION_MAX_ATTEMPTS = 5;

const ALLOWED_PURPOSES = new Set(["register", "forgot-password"]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const OTP_PATTERN = /^\d{6}$/;
const UINT32_RANGE = 0x100000000;
const OTP_SPACE = 1_000_000;
const UNBIASED_UINT32_LIMIT = Math.floor(UINT32_RANGE / OTP_SPACE) * OTP_SPACE;

function requireCrypto(cryptoProvider) {
  if (!cryptoProvider?.getRandomValues || !cryptoProvider?.subtle || !cryptoProvider?.randomUUID) {
    throw new Error("Secure Web Crypto is unavailable.");
  }

  return cryptoProvider;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    return null;
  }

  return Uint8Array.from(
    value.match(/.{2}/g).map((pair) => Number.parseInt(pair, 16)),
  );
}

function buildOtpMessage({ transactionId, target, purpose, otp }) {
  return [
    "grameee-otp-v1",
    transactionId,
    normalizeVerificationPurpose(purpose),
    normalizeVerificationTarget(target),
    String(otp),
  ].join("\u0000");
}

async function importHmacKey(secret, cryptoProvider) {
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error("OTP HMAC secret is not configured securely.");
  }

  return await cryptoProvider.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

async function hmacHex(secret, message, cryptoProvider = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoProvider);
  const key = await importHmacKey(secret, safeCrypto);
  const signature = await safeCrypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message),
  );
  return bytesToHex(new Uint8Array(signature));
}

export function normalizeVerificationTarget(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

export function normalizeVerificationPurpose(value) {
  const normalized = typeof value === "string" ? value.trim().toLowerCase() : "";
  return ALLOWED_PURPOSES.has(normalized) ? normalized : "";
}

export function generateSixDigitOtp(cryptoProvider = globalThis.crypto) {
  const safeCrypto = requireCrypto(cryptoProvider);
  const random = new Uint32Array(1);

  do {
    safeCrypto.getRandomValues(random);
  } while (random[0] >= UNBIASED_UINT32_LIMIT);

  return String(random[0] % OTP_SPACE).padStart(6, "0");
}

export async function buildOtpHash(
  secret,
  { transactionId, target, purpose, otp },
  cryptoProvider = globalThis.crypto,
) {
  return await hmacHex(
    secret,
    buildOtpMessage({ transactionId, target, purpose, otp }),
    cryptoProvider,
  );
}

export async function verifyOtpHash(
  secret,
  { transactionId, target, purpose, otp },
  expectedHash,
  cryptoProvider = globalThis.crypto,
) {
  const safeCrypto = requireCrypto(cryptoProvider);
  const key = await importHmacKey(secret, safeCrypto);
  const signature = hexToBytes(expectedHash);

  if (!signature) {
    await safeCrypto.subtle.verify(
      "HMAC",
      key,
      new Uint8Array(32),
      new TextEncoder().encode(buildOtpMessage({ transactionId, target, purpose, otp })),
    );
    return false;
  }

  return await safeCrypto.subtle.verify(
    "HMAC",
    key,
    signature,
    new TextEncoder().encode(buildOtpMessage({ transactionId, target, purpose, otp })),
  );
}

export async function buildRateLimitKey(
  secret,
  scope,
  value,
  cryptoProvider = globalThis.crypto,
) {
  return await hmacHex(
    secret,
    ["grameee-rate-v1", String(scope), String(value)].join("\u0000"),
    cryptoProvider,
  );
}

export async function buildRecoveryDecoyTarget(
  secret,
  loginId,
  cryptoProvider = globalThis.crypto,
) {
  const normalizedLoginId = typeof loginId === "string"
    ? loginId.trim().toLowerCase()
    : "";
  const decoyKey = await buildRateLimitKey(
    secret,
    "recovery-decoy",
    normalizedLoginId || "missing",
    cryptoProvider,
  );
  return `recovery-${decoyKey.slice(0, 32)}@invalid.local`;
}

export function constantTimeEqualHex(left, right) {
  const a = typeof left === "string" ? left.toLowerCase() : "";
  const b = typeof right === "string" ? right.toLowerCase() : "";
  const length = Math.max(a.length, b.length, 64);
  let difference = a.length ^ b.length;

  for (let index = 0; index < length; index += 1) {
    difference |= (a.charCodeAt(index) || 0) ^ (b.charCodeAt(index) || 0);
  }

  return difference === 0;
}

export async function createVerificationMaterial(
  { secret, target, purpose, originKeySource, now = Date.now() },
  cryptoProvider = globalThis.crypto,
) {
  const safeCrypto = requireCrypto(cryptoProvider);
  const normalizedTarget = normalizeVerificationTarget(target);
  const normalizedPurpose = normalizeVerificationPurpose(purpose);

  if (!normalizedTarget || !normalizedPurpose) {
    throw new Error("Verification target or purpose is invalid.");
  }

  const transactionId = safeCrypto.randomUUID();
  const otp = generateSixDigitOtp(safeCrypto);
  const otpHash = await buildOtpHash(
    secret,
    { transactionId, target: normalizedTarget, purpose: normalizedPurpose, otp },
    safeCrypto,
  );
  const targetRateLimitKey = await buildRateLimitKey(
    secret,
    "target",
    normalizedTarget,
    safeCrypto,
  );
  const originRateLimitKey = await buildRateLimitKey(
    secret,
    "origin",
    originKeySource || "unknown",
    safeCrypto,
  );

  return {
    otp,
    clientResponse: { transactionId },
    row: {
      transaction_id: transactionId,
      normalized_target: normalizedTarget,
      purpose: normalizedPurpose,
      otp_hash: otpHash,
      expires_at: new Date(now + VERIFICATION_TTL_MS).toISOString(),
      attempt_count: 0,
      max_attempts: VERIFICATION_MAX_ATTEMPTS,
      target_rate_limit_key: targetRateLimitKey,
      origin_rate_limit_key: originRateLimitKey,
    },
  };
}

export async function verifyVerificationTransaction(
  { transactionId, target, purpose, otp },
  { secret, store, now = Date.now(), cryptoProvider = globalThis.crypto },
) {
  const normalizedTarget = normalizeVerificationTarget(target);
  const normalizedPurpose = normalizeVerificationPurpose(purpose);
  const normalizedTransactionId = typeof transactionId === "string" ? transactionId.trim() : "";
  const normalizedOtp = typeof otp === "string" ? otp.trim() : "";
  const transaction = UUID_PATTERN.test(normalizedTransactionId)
    ? await store.get(normalizedTransactionId)
    : null;
  const hashMatches = await verifyOtpHash(
    secret,
    {
      transactionId: normalizedTransactionId || "00000000-0000-4000-8000-000000000000",
      target: normalizedTarget,
      purpose: normalizedPurpose || "register",
      otp: normalizedOtp,
    },
    transaction?.otp_hash || "0".repeat(64),
    cryptoProvider,
  );

  if (!transaction) {
    return false;
  }

  const bindingsMatch = transaction.normalized_target === normalizedTarget
    && transaction.purpose === normalizedPurpose;
  const codeFormatValid = OTP_PATTERN.test(normalizedOtp);
  const expiresAt = Date.parse(transaction.expires_at);
  const active = !transaction.consumed_at
    && Number.isFinite(expiresAt)
    && expiresAt > now
    && transaction.attempt_count < transaction.max_attempts;

  if (!active) {
    return false;
  }

  if (!bindingsMatch || !codeFormatValid || !hashMatches) {
    await store.incrementAttempts(
      transaction.transaction_id,
      transaction.attempt_count,
      new Date(now).toISOString(),
    );
    return false;
  }

  return await store.consume(
    transaction.transaction_id,
    transaction.attempt_count,
    new Date(now).toISOString(),
  );
}

export async function claimConsumedVerification(
  { transactionId, target, purpose },
  { store, now = Date.now() },
) {
  const normalizedTransactionId = typeof transactionId === "string" ? transactionId.trim() : "";
  const normalizedTarget = normalizeVerificationTarget(target);
  const normalizedPurpose = normalizeVerificationPurpose(purpose);

  if (!UUID_PATTERN.test(normalizedTransactionId) || !normalizedTarget || !normalizedPurpose) {
    return false;
  }

  return await store.claim(
    normalizedTransactionId,
    normalizedTarget,
    normalizedPurpose,
    new Date(now).toISOString(),
  );
}
