const loginForm = document.getElementById('loginForm');
const loginStatus = document.getElementById('loginStatus');
const sessionStatus = document.getElementById('sessionStatus');
const queueMeta = document.getElementById('queueMeta');
const queueList = document.getElementById('queueList');
const allProcessorsMeta = document.getElementById('allProcessorsMeta');
const allProcessorsList = document.getElementById('allProcessorsList');
const sessionPanel = document.getElementById('sessionPanel');
const queuePanel = document.getElementById('queuePanel');
const allProcessorsPanel = document.getElementById('allProcessorsPanel');
const signOutButton = document.getElementById('signOutButton');
const refreshQueueButton = document.getElementById('refreshQueue');
const queueSearch = document.getElementById('queueSearch');
const allProcessorsSearch = document.getElementById('allProcessorsSearch');
const editProcessorModal = document.getElementById('editProcessorModal');
const editProcessorForm = document.getElementById('editProcessorForm');
const editProcessorStatus = document.getElementById('editProcessorStatus');
const editProcessorId = document.getElementById('editProcessorId');
const editProcessorName = document.getElementById('editProcessorName');
const editProcessorInputs = document.getElementById('editProcessorInputs');
const editProcessorOutputs = document.getElementById('editProcessorOutputs');
const editProcessorTime = document.getElementById('editProcessorTime');
const editProcessorDescription = document.getElementById('editProcessorDescription');

const ADMIN_SESSION_KEY = 'gre-admin-session';
const ADMIN_API_URL = `${String(window.APP_CONFIG?.SUPABASE_URL || '').replace(/\/$/, '')}/functions/v1/grameee-admin`;
const ADMIN_API_KEY = String(window.APP_CONFIG?.SUPABASE_ANON_KEY || '');
let processorCache = new Map();
let pendingProcessors = [];
let allProcessors = [];

function normalizeText(value) {
  return (value || '').trim();
}

function setStatus(element, message, isError = false) {
  element.textContent = message;
  element.classList.toggle('error', Boolean(isError));
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatDate(value) {
  if (!value) return 'Unknown date';
  return new Date(value).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}

function matchesProcessorSearch(item, query) {
  const haystack = [
    item.name,
    ...(item.inputs || []),
    ...(item.outputs || []),
    item.description,
    item.processing_time,
    item.status,
    item.submitted_by
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  return haystack.includes(query.toLowerCase());
}

function getStoredToken() {
  return window.sessionStorage.getItem(ADMIN_SESSION_KEY) || '';
}

function storeToken(token) {
  if (token) {
    window.sessionStorage.setItem(ADMIN_SESSION_KEY, token);
    return;
  }
  window.sessionStorage.removeItem(ADMIN_SESSION_KEY);
}

function updateSessionUi(isSignedIn) {
  loginForm.style.display = isSignedIn ? 'none' : 'grid';
  sessionPanel.classList.toggle('active', Boolean(isSignedIn));
  queuePanel.classList.toggle('active', Boolean(isSignedIn));
  allProcessorsPanel.classList.toggle('active', Boolean(isSignedIn));
}

async function adminRequest(action, payload = {}) {
  const response = await fetch(ADMIN_API_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: ADMIN_API_KEY,
      Authorization: `Bearer ${ADMIN_API_KEY}`
    },
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

function renderQueue(items) {
  queueList.innerHTML = '';
  if (!items.length) {
    queueList.innerHTML = '<article class="admin-card"><p>No pending processor submissions right now.</p></article>';
    return;
  }

  items.forEach((item) => {
    const card = document.createElement('article');
    card.className = 'admin-card';
    card.innerHTML = `
      <div class="admin-card-header">
        <h4>${escapeHtml(item.name)}</h4>
        <span class="admin-badge">Pending</span>
      </div>
      <p><strong>Inputs:</strong> ${escapeHtml((item.inputs || []).join(', '))}</p>
      <p><strong>Outputs:</strong> ${escapeHtml((item.outputs || []).join(', '))}</p>
      <p><strong>Processing Time:</strong> ${escapeHtml(item.processing_time || 'N/A')}</p>
      <p><strong>Description:</strong> ${escapeHtml(item.description || 'No description provided.')}</p>
      <p><strong>Submitted By:</strong> ${escapeHtml(item.submitted_by || 'Anonymous')}</p>
      <p><strong>Submitted:</strong> ${escapeHtml(formatDate(item.created_at))}</p>
      <div class="btn-group">
        <button class="btn btn-warning btn-small" type="button" data-edit-processor="${item.id}">Edit</button>
        <button class="btn btn-success btn-small" type="button" data-approve="${item.id}">Approve</button>
        <button class="btn btn-danger btn-small" type="button" data-reject="${item.id}">Reject</button>
      </div>
    `;
    queueList.appendChild(card);
  });
}

function renderAllProcessors(items) {
  allProcessorsList.innerHTML = '';
  if (!items.length) {
    allProcessorsList.innerHTML = '<article class="admin-card"><p>No processor records found.</p></article>';
    return;
  }

  items.forEach((item) => {
    const card = document.createElement('article');
    card.className = 'admin-card';
    card.innerHTML = `
      <div class="admin-card-header">
        <h4>${escapeHtml(item.name)}</h4>
        <span class="admin-badge ${item.status === 'approved' ? 'approved' : 'pending'}">${escapeHtml(item.status || 'unknown')}</span>
      </div>
      <p><strong>Inputs:</strong> ${escapeHtml((item.inputs || []).join(', '))}</p>
      <p><strong>Outputs:</strong> ${escapeHtml((item.outputs || []).join(', '))}</p>
      <p><strong>Processing Time:</strong> ${escapeHtml(item.processing_time || 'N/A')}</p>
      <p><strong>Description:</strong> ${escapeHtml(item.description || 'No description provided.')}</p>
      <p><strong>Updated:</strong> ${escapeHtml(formatDate(item.updated_at || item.created_at))}</p>
      <div class="btn-group">
        <button class="btn btn-warning btn-small" type="button" data-edit-processor="${item.id}">Edit</button>
        <button class="btn btn-danger btn-small" type="button" data-delete-processor="${item.id}">Delete</button>
      </div>
    `;
    allProcessorsList.appendChild(card);
  });
}

async function verifySession() {
  const token = getStoredToken();
  if (!token) {
    updateSessionUi(false);
    document.body.classList.remove('auth-loading');
    return false;
  }

  try {
    const data = await adminRequest('verify', { token });
    if (!data?.valid) throw new Error('Session invalid');
    updateSessionUi(true);
    document.body.classList.remove('auth-loading');
    return true;
  } catch {
    storeToken('');
    updateSessionUi(false);
    queueMeta.textContent = 'Your admin session has expired. Please sign in again.';
    allProcessorsMeta.textContent = 'Your admin session has expired. Please sign in again.';
    document.body.classList.remove('auth-loading');
    return false;
  }
}

async function loadPendingQueue() {
  const token = getStoredToken();
  if (!token) {
    queueMeta.textContent = 'Sign in as admin to load pending submissions.';
    queueList.innerHTML = '';
    return;
  }
  queueMeta.textContent = 'Loading pending submissions...';
  try {
    const data = await adminRequest('listPendingProcessors', { token });
    const items = Array.isArray(data?.items) ? data.items : [];
    pendingProcessors = items;
    items.forEach((item) => processorCache.set(item.id, item));
    queueMeta.textContent = `${items.length} pending submission${items.length === 1 ? '' : 's'} in the queue`;
    renderQueue(items.filter((item) => matchesProcessorSearch(item, normalizeText(queueSearch.value || ''))));
  } catch (error) {
    queueMeta.textContent = error.message || 'Pending submissions could not be loaded.';
  }
}

async function loadAllProcessors() {
  const token = getStoredToken();
  if (!token) {
    allProcessorsMeta.textContent = 'Sign in as admin to load all processors.';
    allProcessorsList.innerHTML = '';
    return;
  }
  allProcessorsMeta.textContent = 'Loading all processor records...';
  try {
    const data = await adminRequest('listAllProcessors', { token });
    const items = Array.isArray(data?.items) ? data.items : [];
    allProcessors = items;
    processorCache = new Map(items.map((item) => [item.id, item]));
    allProcessorsMeta.textContent = `${items.length} processor record${items.length === 1 ? '' : 's'} found`;
    renderAllProcessors(items.filter((item) => matchesProcessorSearch(item, normalizeText(allProcessorsSearch.value || ''))));
  } catch (error) {
    allProcessorsMeta.textContent = error.message || 'Processor records could not be loaded.';
  }
}

async function approveProcessor(id) {
  try {
    await adminRequest('approveProcessor', { token: getStoredToken(), processorId: id });
    setStatus(sessionStatus, 'Processor approved and now visible in the public directory.');
    await loadPendingQueue();
    await loadAllProcessors();
  } catch (error) {
    setStatus(sessionStatus, error.message || 'Processor could not be approved.', true);
  }
}

async function rejectProcessor(id) {
  try {
    await adminRequest('rejectProcessor', { token: getStoredToken(), processorId: id });
    setStatus(sessionStatus, 'Pending processor rejected and removed.');
    await loadPendingQueue();
    await loadAllProcessors();
  } catch (error) {
    setStatus(sessionStatus, error.message || 'Processor could not be rejected.', true);
  }
}

async function deleteProcessor(id) {
  try {
    await adminRequest('deleteProcessor', { token: getStoredToken(), processorId: id });
    setStatus(sessionStatus, 'Processor deleted.');
    await loadPendingQueue();
    await loadAllProcessors();
  } catch (error) {
    setStatus(sessionStatus, error.message || 'Processor could not be deleted.', true);
  }
}

function openEditProcessor(id) {
  const processor = processorCache.get(id);
  if (!processor) {
    setStatus(sessionStatus, 'Processor details could not be loaded.', true);
    return;
  }
  editProcessorId.value = processor.id;
  editProcessorName.value = processor.name || '';
  editProcessorInputs.value = (processor.inputs || []).join(', ');
  editProcessorOutputs.value = (processor.outputs || []).join(', ');
  editProcessorTime.value = processor.processing_time || '';
  editProcessorDescription.value = processor.description || '';
  setStatus(editProcessorStatus, '');
  editProcessorModal.classList.remove('hidden');
}

function closeEditProcessor() {
  editProcessorForm.reset();
  editProcessorId.value = '';
  setStatus(editProcessorStatus, '');
  editProcessorModal.classList.add('hidden');
}

async function updateProcessor() {
  const processorId = normalizeText(editProcessorId.value);
  const name = normalizeText(editProcessorName.value);
  const inputs = editProcessorInputs.value.split(',').map((item) => item.trim()).filter(Boolean);
  const outputs = editProcessorOutputs.value.split(',').map((item) => item.trim()).filter(Boolean);
  const processingTime = normalizeText(editProcessorTime.value);
  const description = normalizeText(editProcessorDescription.value);

  if (!processorId || !name || !inputs.length || !outputs.length) {
    setStatus(editProcessorStatus, 'Name, inputs, and outputs are required.', true);
    return;
  }

  setStatus(editProcessorStatus, 'Saving changes...');
  try {
    await adminRequest('updateProcessor', {
      token: getStoredToken(),
      processorId,
      name,
      inputs,
      outputs,
      processingTime,
      description
    });
    setStatus(sessionStatus, 'Processor updated successfully.');
    closeEditProcessor();
    await loadPendingQueue();
    await loadAllProcessors();
  } catch (error) {
    setStatus(editProcessorStatus, error.message || 'Processor could not be updated.', true);
  }
}

queueList.addEventListener('click', async (event) => {
  const editId = event.target.closest('[data-edit-processor]')?.dataset.editProcessor;
  const approveId = event.target.closest('[data-approve]')?.dataset.approve;
  const rejectId = event.target.closest('[data-reject]')?.dataset.reject;
  if (editId) openEditProcessor(editId);
  if (approveId) await approveProcessor(approveId);
  if (rejectId) await rejectProcessor(rejectId);
});

allProcessorsList.addEventListener('click', async (event) => {
  const editId = event.target.closest('[data-edit-processor]')?.dataset.editProcessor;
  const deleteId = event.target.closest('[data-delete-processor]')?.dataset.deleteProcessor;
  if (editId) openEditProcessor(editId);
  if (deleteId) await deleteProcessor(deleteId);
});

editProcessorModal.addEventListener('click', (event) => {
  if (event.target.closest('[data-close-edit]')) closeEditProcessor();
});

editProcessorForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  await updateProcessor();
});

queueSearch.addEventListener('input', () => {
  renderQueue(pendingProcessors.filter((item) => matchesProcessorSearch(item, normalizeText(queueSearch.value))));
});

allProcessorsSearch.addEventListener('input', () => {
  renderAllProcessors(allProcessors.filter((item) => matchesProcessorSearch(item, normalizeText(allProcessorsSearch.value))));
});

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = normalizeText(document.getElementById('adminPassword').value);
  if (!password) {
    setStatus(loginStatus, 'Enter the admin password.', true);
    return;
  }
  setStatus(loginStatus, 'Signing in...');
  try {
    const data = await adminRequest('login', { password });
    if (!data?.token) throw new Error('Admin login failed.');
    storeToken(data.token);
    document.getElementById('adminPassword').value = '';
    updateSessionUi(true);
    setStatus(loginStatus, 'Signed in successfully.');
    await loadPendingQueue();
    await loadAllProcessors();
  } catch (error) {
    setStatus(loginStatus, error.message || 'Admin login failed.', true);
  }
});

signOutButton.addEventListener('click', async () => {
  const token = getStoredToken();
  try {
    if (token) await adminRequest('logout', { token });
  } catch {
    // Ignore sign-out cleanup errors.
  }
  storeToken('');
  updateSessionUi(false);
  queueMeta.textContent = 'Sign in as admin to load pending submissions.';
  queueList.innerHTML = '';
  allProcessorsMeta.textContent = 'Sign in as admin to load all processors.';
  allProcessorsList.innerHTML = '';
  setStatus(sessionStatus, '');
  setStatus(loginStatus, '');
  closeEditProcessor();
});

refreshQueueButton.addEventListener('click', async () => {
  await loadPendingQueue();
  await loadAllProcessors();
});

(async () => {
  const valid = await verifySession();
  if (valid) {
    await loadPendingQueue();
    await loadAllProcessors();
  }
})();
