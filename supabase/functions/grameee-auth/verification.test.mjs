import assert from "node:assert/strict";
import test from "node:test";
import {
  buildOtpHash,
  buildRecoveryDecoyTarget,
  claimConsumedVerification,
  constantTimeEqualHex,
  createVerificationMaterial,
  generateSixDigitOtp,
  verifyOtpHash,
  verifyVerificationTransaction,
} from "./verification.mjs";

const TEST_SECRET = "test-only-secret-that-is-longer-than-thirty-two-bytes";
const NOW = Date.parse("2026-11-14T00:00:00.000Z");

function createStore(rows) {
  const state = new Map(rows.map((row) => [row.transaction_id, { ...row }]));
  return {
    state,
    async get(transactionId) {
      const row = state.get(transactionId);
      return row ? { ...row } : null;
    },
    async incrementAttempts(transactionId, expectedAttemptCount, nowIso) {
      const row = state.get(transactionId);
      if (!row || row.consumed_at || Date.parse(row.expires_at) <= Date.parse(nowIso)
        || row.attempt_count !== expectedAttemptCount || row.attempt_count >= row.max_attempts) {
        return false;
      }
      row.attempt_count += 1;
      return true;
    },
    async consume(transactionId, expectedAttemptCount, nowIso) {
      const row = state.get(transactionId);
      if (!row || row.consumed_at || Date.parse(row.expires_at) <= Date.parse(nowIso)
        || row.attempt_count !== expectedAttemptCount || row.attempt_count >= row.max_attempts) {
        return false;
      }
      row.consumed_at = nowIso;
      return true;
    },
    async claim(transactionId, target, purpose, nowIso) {
      const row = state.get(transactionId);
      if (!row || !row.consumed_at || Date.parse(row.expires_at) <= Date.parse(nowIso)
        || row.normalized_target !== target || row.purpose !== purpose) {
        return false;
      }
      state.delete(transactionId);
      return true;
    },
  };
}

test("secure OTP generation always returns six digits", () => {
  for (let index = 0; index < 1_000; index += 1) {
    assert.match(generateSixDigitOtp(), /^\d{6}$/);
  }
});

test("client response contains only an opaque transaction ID", async () => {
  const material = await createVerificationMaterial({
    secret: TEST_SECRET,
    target: " Person@Example.COM ",
    purpose: "register",
    originKeySource: "test-origin",
    now: NOW,
  });
  const serialized = JSON.stringify(material.clientResponse);

  assert.deepEqual(Object.keys(material.clientResponse), ["transactionId"]);
  assert.match(material.clientResponse.transactionId, /^[0-9a-f-]{36}$/i);
  assert.equal(serialized.includes(material.otp), false);
  assert.equal(serialized.includes(material.row.otp_hash), false);
  assert.equal(material.row.normalized_target, "person@example.com");
  assert.match(material.row.otp_hash, /^[0-9a-f]{64}$/);
});

test("recovery decoy targets are deterministic and do not expose identifiers", async () => {
  const first = await buildRecoveryDecoyTarget(TEST_SECRET, " MissingUser ");
  const second = await buildRecoveryDecoyTarget(TEST_SECRET, "missinguser");

  assert.equal(first, second);
  assert.match(first, /^recovery-[0-9a-f]{32}@invalid\.local$/);
  assert.equal(first.includes("missinguser"), false);
});

test("hash comparison is exact and purpose/target bound", async () => {
  const transactionId = "11111111-1111-4111-8111-111111111111";
  const correct = await buildOtpHash(TEST_SECRET, {
    transactionId,
    target: "person@example.com",
    purpose: "register",
    otp: "123456",
  });
  const swappedPurpose = await buildOtpHash(TEST_SECRET, {
    transactionId,
    target: "person@example.com",
    purpose: "forgot-password",
    otp: "123456",
  });

  assert.equal(constantTimeEqualHex(correct, correct), true);
  assert.equal(constantTimeEqualHex(correct, swappedPurpose), false);
  assert.equal(constantTimeEqualHex(correct, correct.slice(0, -1)), false);
  assert.equal(await verifyOtpHash(TEST_SECRET, {
    transactionId,
    target: "person@example.com",
    purpose: "register",
    otp: "123456",
  }, correct), true);
  assert.equal(await verifyOtpHash(TEST_SECRET, {
    transactionId,
    target: "person@example.com",
    purpose: "forgot-password",
    otp: "123456",
  }, correct), false);
});

test("wrong and swapped inputs consume attempts; correct code succeeds once", async () => {
  const transactionId = "22222222-2222-4222-8222-222222222222";
  const otp = "654321";
  const row = {
    transaction_id: transactionId,
    normalized_target: "person@example.com",
    purpose: "register",
    otp_hash: await buildOtpHash(TEST_SECRET, {
      transactionId,
      target: "person@example.com",
      purpose: "register",
      otp,
    }),
    expires_at: new Date(NOW + 600_000).toISOString(),
    attempt_count: 0,
    max_attempts: 5,
    consumed_at: null,
  };
  const store = createStore([row]);
  const dependencies = { secret: TEST_SECRET, store, now: NOW };

  assert.equal(await verifyVerificationTransaction({
    transactionId, target: "person@example.com", purpose: "register", otp: "000000",
  }, dependencies), false);
  assert.equal(store.state.get(transactionId).attempt_count, 1);

  assert.equal(await verifyVerificationTransaction({
    transactionId, target: "person@example.com", purpose: "forgot-password", otp,
  }, dependencies), false);
  assert.equal(store.state.get(transactionId).attempt_count, 2);

  assert.equal(await verifyVerificationTransaction({
    transactionId, target: "other@example.com", purpose: "register", otp,
  }, dependencies), false);
  assert.equal(store.state.get(transactionId).attempt_count, 3);

  assert.equal(await verifyVerificationTransaction({
    transactionId, target: "person@example.com", purpose: "register", otp,
  }, dependencies), true);
  assert.ok(store.state.get(transactionId).consumed_at);

  assert.equal(await verifyVerificationTransaction({
    transactionId, target: "person@example.com", purpose: "register", otp,
  }, dependencies), false);
});

test("expired and exhausted transactions fail", async () => {
  const expiredId = "33333333-3333-4333-8333-333333333333";
  const exhaustedId = "44444444-4444-4444-8444-444444444444";
  const makeRow = async (transactionId, expiresAt, attemptCount) => ({
    transaction_id: transactionId,
    normalized_target: "person@example.com",
    purpose: "register",
    otp_hash: await buildOtpHash(TEST_SECRET, {
      transactionId,
      target: "person@example.com",
      purpose: "register",
      otp: "123456",
    }),
    expires_at: expiresAt,
    attempt_count: attemptCount,
    max_attempts: 5,
    consumed_at: null,
  });
  const store = createStore([
    await makeRow(expiredId, new Date(NOW - 1).toISOString(), 0),
    await makeRow(exhaustedId, new Date(NOW + 600_000).toISOString(), 5),
  ]);
  const dependencies = { secret: TEST_SECRET, store, now: NOW };

  assert.equal(await verifyVerificationTransaction({
    transactionId: expiredId, target: "person@example.com", purpose: "register", otp: "123456",
  }, dependencies), false);
  assert.equal(await verifyVerificationTransaction({
    transactionId: exhaustedId, target: "person@example.com", purpose: "register", otp: "123456",
  }, dependencies), false);
});

test("consumed verification can be claimed once with the same target and purpose", async () => {
  const transactionId = "55555555-5555-4555-8555-555555555555";
  const row = {
    transaction_id: transactionId,
    normalized_target: "person@example.com",
    purpose: "register",
    otp_hash: "0".repeat(64),
    expires_at: new Date(NOW + 600_000).toISOString(),
    attempt_count: 0,
    max_attempts: 5,
    consumed_at: new Date(NOW).toISOString(),
  };
  const store = createStore([row]);
  const dependencies = { store, now: NOW + 1 };

  assert.equal(await claimConsumedVerification({
    transactionId, target: "person@example.com", purpose: "forgot-password",
  }, dependencies), false);
  assert.equal(await claimConsumedVerification({
    transactionId, target: "other@example.com", purpose: "register",
  }, dependencies), false);
  assert.equal(await claimConsumedVerification({
    transactionId, target: "person@example.com", purpose: "register",
  }, dependencies), true);
  assert.equal(await claimConsumedVerification({
    transactionId, target: "person@example.com", purpose: "register",
  }, dependencies), false);
});
