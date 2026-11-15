import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPasswordResetNotification,
  completePasswordResetSecurity,
} from "./recovery-security.mjs";

const USER_ID = "11111111-1111-4111-8111-111111111111";
const NOW = new Date("2026-11-15T10:30:00.000Z");

function dependencies(overrides = {}) {
  const calls = [];
  return {
    calls,
    value: {
      revokeSessions: async () => { calls.push("revoke"); return 3; },
      updatePassword: async () => { calls.push("update"); },
      sendNotification: async () => { calls.push("notify"); },
      writeAudit: async (event) => { calls.push(["audit", event]); },
      randomUUID: () => "22222222-2222-4222-8222-222222222222",
      now: () => NOW,
      onOperationalError: (message) => calls.push(["operational-error", message]),
      ...overrides,
    },
  };
}

test("password-reset notice reports session revocation without secrets", () => {
  const notice = buildPasswordResetNotification(NOW).join("\n");
  assert.match(notice, /All existing sign-in sessions were ended/);
  assert.match(notice, /2026-11-15T10:30:00.000Z/);
  assert.doesNotMatch(notice, /password:|token|verification code/i);
});

test("successful reset revokes sessions before update and records notification", async () => {
  const deps = dependencies();
  const result = await completePasswordResetSecurity({
    userId: USER_ID,
    userEmail: "controlled@example.test",
    newPassword: "Strong1!Password",
    requestMetadata: { source: "test" },
  }, deps.value);

  assert.deepEqual(deps.calls.slice(0, 3), ["revoke", "update", "notify"]);
  const audit = deps.calls[3][1];
  assert.equal(audit.outcome, "success");
  assert.equal(audit.sessions_revoked, 3);
  assert.equal(audit.notification_sent, true);
  assert.deepEqual(result, { sessionsRevoked: 3, notificationSent: true, auditRecorded: true });
});

test("notification failure does not reverse a completed secure reset", async () => {
  const deps = dependencies({
    sendNotification: async () => { deps.calls.push("notify"); throw new Error("mail unavailable"); },
  });
  const result = await completePasswordResetSecurity({
    userId: USER_ID,
    userEmail: "controlled@example.test",
    newPassword: "Strong1!Password",
    requestMetadata: {},
  }, deps.value);

  const audit = deps.calls.find((entry) => Array.isArray(entry) && entry[0] === "audit")[1];
  assert.equal(audit.outcome, "success");
  assert.equal(audit.notification_sent, false);
  assert.equal(result.notificationSent, false);
});

test("session revocation failure prevents password mutation and is audited", async () => {
  const deps = dependencies({
    revokeSessions: async () => { deps.calls.push("revoke"); throw new Error("revoke failed"); },
  });

  await assert.rejects(() => completePasswordResetSecurity({
    userId: USER_ID,
    userEmail: "controlled@example.test",
    newPassword: "Strong1!Password",
    requestMetadata: {},
  }, deps.value), /revoke failed/);
  assert.equal(deps.calls.includes("update"), false);
  const audit = deps.calls.find((entry) => Array.isArray(entry) && entry[0] === "audit")[1];
  assert.equal(audit.outcome, "failure");
  assert.equal(audit.failure_phase, "session_revoke");
});
