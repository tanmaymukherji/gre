function normalizeOperationalError(error) {
  return error instanceof Error ? error.message : "Password recovery operation failed.";
}

async function recordAuditSafely(writeAudit, event, onOperationalError) {
  try {
    await writeAudit(event);
    return true;
  } catch (error) {
    onOperationalError(normalizeOperationalError(error));
    return false;
  }
}

export function buildPasswordResetNotification(now = new Date()) {
  return [
    "Your GramEEE account password was reset successfully.",
    "",
    `Reset completed: ${now.toISOString()}`,
    "All existing sign-in sessions were ended. Please sign in again with your new password.",
    "",
    "If you did not request this change, contact the GramEEE support team immediately.",
  ];
}

export async function completePasswordResetSecurity(
  { userId, userEmail, newPassword, requestMetadata },
  {
    revokeSessions,
    updatePassword,
    sendNotification,
    writeAudit,
    randomUUID = () => globalThis.crypto.randomUUID(),
    now = () => new Date(),
    onOperationalError = () => {},
  },
) {
  const correlationId = randomUUID();
  let sessionsRevoked = 0;

  try {
    sessionsRevoked = await revokeSessions(userId);
  } catch (error) {
    await recordAuditSafely(writeAudit, {
      correlation_id: correlationId,
      event_type: "password_reset",
      outcome: "failure",
      user_id: userId,
      sessions_revoked: 0,
      notification_sent: false,
      failure_phase: "session_revoke",
      request_metadata: requestMetadata,
      occurred_at: now().toISOString(),
    }, onOperationalError);
    throw error;
  }

  try {
    await updatePassword(userId, newPassword);
  } catch (error) {
    await recordAuditSafely(writeAudit, {
      correlation_id: correlationId,
      event_type: "password_reset",
      outcome: "failure",
      user_id: userId,
      sessions_revoked: sessionsRevoked,
      notification_sent: false,
      failure_phase: "password_update",
      request_metadata: requestMetadata,
      occurred_at: now().toISOString(),
    }, onOperationalError);
    throw error;
  }

  let notificationSent = true;
  try {
    await sendNotification(userEmail, buildPasswordResetNotification(now()));
  } catch (error) {
    notificationSent = false;
    onOperationalError(normalizeOperationalError(error));
  }

  const auditRecorded = await recordAuditSafely(writeAudit, {
    correlation_id: correlationId,
    event_type: "password_reset",
    outcome: "success",
    user_id: userId,
    sessions_revoked: sessionsRevoked,
    notification_sent: notificationSent,
    failure_phase: null,
    request_metadata: requestMetadata,
    occurred_at: now().toISOString(),
  }, onOperationalError);

  return { sessionsRevoked, notificationSent, auditRecorded };
}
