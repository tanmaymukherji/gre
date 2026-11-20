import assert from "node:assert/strict";
import test from "node:test";
import {
  EXCHANGE_TTL_MS,
  PRIVILEGED_ABSOLUTE_MS,
  STANDARD_ABSOLUTE_MS,
  generateOpaqueToken,
  hashClientSecret,
  isExactRedirectAllowed,
  isExchangeToken,
  isPkceVerifier,
  issueMaterial,
  keyedHash,
  normalizePrivileges,
  sessionMaterial,
  sha256Base64Url,
  verifyClientSecret,
} from "./exchange.mjs";

const secret = "test-only-session-exchange-secret-with-more-than-32-characters";
const verifier = "a".repeat(64);

test("opaque exchange and session tokens contain 256 random bits", () => {
  const first = generateOpaqueToken();
  const second = generateOpaqueToken();
  assert.match(first, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(first, second);
  assert.equal(isExchangeToken(first), true);
});

test("PKCE accepts RFC verifier shape and derives an S256 challenge", async () => {
  assert.equal(isPkceVerifier(verifier), true);
  assert.equal(isPkceVerifier("short"), false);
  assert.match(await sha256Base64Url(verifier), /^[A-Za-z0-9_-]{43}$/);
});

test("redirect matching is exact and HTTPS only", () => {
  const registered = ["https://askgre.grameee.org/auth/callback"];
  assert.equal(isExactRedirectAllowed(registered[0], registered), true);
  assert.equal(isExactRedirectAllowed(`${registered[0]}?next=/`, registered), false);
  assert.equal(isExactRedirectAllowed("https://askgre.grameee.org.evil.test/auth/callback", registered), false);
  assert.equal(isExactRedirectAllowed("http://askgre.grameee.org/auth/callback", ["http://askgre.grameee.org/auth/callback"]), false);
});

test("client secrets are domain-separated and verified without plaintext storage", async () => {
  const hash = await hashClientSecret(secret, "askgre", "x".repeat(48));
  assert.match(hash, /^[0-9a-f]{64}$/);
  assert.equal(await verifyClientSecret(secret, "askgre", "x".repeat(48), hash), true);
  assert.equal(await verifyClientSecret(secret, "askgre", "y".repeat(48), hash), false);
  assert.notEqual(hash, await keyedHash(secret, "exchange-code", ["x".repeat(48)]));
});

test("issued material is audience-bound, hashed, and expires in 60 seconds", async () => {
  const now = Date.parse("2026-11-20T00:00:00.000Z");
  const challenge = await sha256Base64Url(verifier);
  const material = await issueMaterial({
    secret,
    userId: "11111111-1111-4111-8111-111111111111",
    sessionId: "22222222-2222-4222-8222-222222222222",
    clientId: "askgre",
    audience: "askgre.grameee.org",
    redirectUri: "https://askgre.grameee.org/auth/callback",
    pkceChallenge: challenge,
    contextSource: "test-context",
    now,
  });
  assert.equal(material.row.client_id, "askgre");
  assert.equal(material.row.audience, "askgre.grameee.org");
  assert.match(material.row.code_hash, /^[0-9a-f]{64}$/);
  assert.equal(Date.parse(material.row.expires_at) - Date.parse(material.row.issued_at), EXCHANGE_TTL_MS);
  assert.equal(material.row.code_hash.includes(material.code), false);
});

test("standard and administrator application sessions receive bounded lifetimes", async () => {
  const now = Date.parse("2026-11-20T00:00:00.000Z");
  const standard = await sessionMaterial({ secret, role: "user", now });
  const privileged = await sessionMaterial({ secret, role: "admin", now });
  assert.equal(Date.parse(standard.absoluteExpiresAt) - now, STANDARD_ABSOLUTE_MS);
  assert.equal(Date.parse(privileged.absoluteExpiresAt) - now, PRIVILEGED_ABSOLUTE_MS);
  assert.match(standard.sessionTokenHash, /^[0-9a-f]{64}$/);
  assert.equal(standard.sessionTokenHash.includes(standard.sessionToken), false);
});

test("trusted privilege defaults preserve current Grameee behavior and honor denials", () => {
  assert.deepEqual(normalizePrivileges({}, "user"), {
    ecosystem: true,
    askGre: true,
    offerSolutions: true,
    askHelp: true,
    needsMap: true,
    gre: false,
  });
  assert.equal(normalizePrivileges({ askGre: false }, "user").askGre, false);
  assert.equal(normalizePrivileges({}, "curator").gre, true);
  assert.equal(normalizePrivileges({ askGre: false, gre: false }, "admin").askGre, true);
});
