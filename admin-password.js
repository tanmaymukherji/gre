const changePasswordForm = document.getElementById('changePasswordForm');
const changePasswordStatus = document.getElementById('changePasswordStatus');

const ADMIN_SESSION_KEY = 'gre-admin-session';
const ADMIN_API_URL = `${String(window.APP_CONFIG?.SUPABASE_URL || '').replace(/\/$/, '')}/functions/v1/grameee-admin`;

function normalizeText(value) {
  return (value || '').trim();
}

function setStatus(message, isError = false) {
  changePasswordStatus.textContent = message;
  changePasswordStatus.classList.toggle('error', Boolean(isError));
}

function getStoredToken() {
  return window.sessionStorage.getItem(ADMIN_SESSION_KEY) || '';
}

async function adminRequest(action, payload = {}) {
  const response = await fetch(ADMIN_API_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action, ...payload })
  });
  let data = null;
  try {
    data = await response.json();
  } catch {
    data = null;
  }
  if (!response.ok) throw new Error(data?.error || 'Admin request failed.');
  return data;
}

async function verifySession() {
  const token = getStoredToken();
  if (!token) {
    window.location.href = './admin-tools.html';
    return;
  }
  try {
    const data = await adminRequest('verify', { token });
    if (!data?.valid) window.location.href = './admin-tools.html';
  } catch {
    window.location.href = './admin-tools.html';
  }
}

changePasswordForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const currentPassword = normalizeText(document.getElementById('currentPassword').value);
  const newPassword = normalizeText(document.getElementById('newPassword').value);
  const confirmPassword = normalizeText(document.getElementById('confirmPassword').value);

  if (!currentPassword || !newPassword) {
    setStatus('Current password and new password are required.', true);
    return;
  }
  if (newPassword.length < 10) {
    setStatus('Use a new password with at least 10 characters.', true);
    return;
  }
  if (newPassword !== confirmPassword) {
    setStatus('The new password fields do not match.', true);
    return;
  }

  setStatus('Updating password...');
  try {
    await adminRequest('changePassword', {
      token: getStoredToken(),
      currentPassword,
      newPassword
    });
    changePasswordForm.reset();
    setStatus('Admin password updated successfully.');
  } catch (error) {
    setStatus(error.message || 'Password update failed.', true);
  }
});

verifySession();
