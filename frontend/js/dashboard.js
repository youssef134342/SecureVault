// dashboard.js — all dashboard page logic

requireAuth();

const user = getUser();

function uint8ToBase64(bytes) {
  const chunk = 8192;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunk) {
    const end = Math.min(i + chunk, bytes.length);
    binary += String.fromCharCode.apply(null, bytes.subarray(i, end));
  }
  return btoa(binary);
}

// ── Init ──────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  if (!user) { window.location.href = '/index.html'; return; }

  // Sidebar user info
  document.getElementById('sidebar-avatar').textContent   = user.username[0].toUpperCase();
  document.getElementById('sidebar-username').textContent = user.username;
  document.getElementById('sidebar-role').textContent     = user.role.charAt(0).toUpperCase() + user.role.slice(1);

  // Show admin nav
  if (user.role === 'admin' || user.role === 'manager') {
    document.getElementById('admin-nav').style.display = 'block';
  }

  loadDashboard();
});

// ── Page switching ─────────────────────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('.page-section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const section = document.getElementById('page-' + name);
  if (section) section.classList.add('active');

  document.querySelectorAll('.nav-item').forEach(btn => {
    if (btn.textContent.toLowerCase().includes(name === 'dashboard' ? 'dashboard' :
        name === 'documents' ? 'documents' :
        name === 'upload' ? 'upload' :
        name === 'verify' ? 'verify' :
        name === 'users' ? 'user' :
        name === 'audit' ? 'audit' :
        name === 'security' ? 'security' : '___')) {
      btn.classList.add('active');
    }
  });

  // Lazy load
  if (name === 'documents') loadDocuments();
  if (name === 'users' && (user.role === 'admin' || user.role === 'manager')) loadUsers();
  if (name === 'audit' && user.role === 'admin') loadAuditLogs();
  if (name === 'verify') loadVerifySelect();
  if (name === 'security') loadSecurityPage();
}

// ── Logout ────────────────────────────────────────────────────────────────────
async function logout() {
  await api.logout();
  clearAuth();
  window.location.href = '/index.html';
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
async function loadDashboard() {
  // 2FA status (MANDATORY)
  const twoFaCard = document.getElementById('2fa-status-card');
  if (twoFaCard) {
    twoFaCard.textContent = '🛡️ 2FA: Mandatory ✓';
  }

  // Load docs
  const { ok, data } = await api.listDocs();
  if (ok) {
    document.getElementById('stat-docs').textContent = data.documents.length;
    document.getElementById('stat-enc').textContent  = data.documents.length; // all encrypted

    // Recent docs (last 5)
    const recent = data.documents.slice(0, 5);
    const container = document.getElementById('recent-docs-list');
    if (recent.length === 0) {
      container.innerHTML = '<div class="empty-state" style="padding:24px"><p>No documents yet. <button class="btn-secondary" onclick="showPage(\'upload\')">Upload your first</button></p></div>';
    } else {
      container.innerHTML = `<div class="table-wrap"><table>
        <thead><tr><th>File</th><th>Size</th><th>Uploaded</th><th style="text-align:right">Actions</th></tr></thead>
        <tbody>${recent.map(d => `
          <tr>
            <td><span style="margin-right:8px">${fileIcon(d.original_name)}</span>${truncate(d.original_name, 35)}</td>
            <td class="mono">${formatSize(d.file_size)}</td>
            <td class="mono">${formatDate(d.uploaded_at)}</td>
            <td style="text-align:right">
              <button class="btn-icon" onclick="downloadDoc('${d.uuid}','${d.original_name}')" title="Download">⬇️</button>
              <button class="btn-icon" onclick="quickVerify('${d.uuid}')" title="Verify">✅</button>
            </td>
          </tr>`).join('')}
        </tbody></table></div>`;
    }
  }

  // Admin stats
  if (user.role === 'admin' || user.role === 'manager') {
    document.getElementById('stat-card-users').style.display  = 'block';
    document.getElementById('stat-card-recent').style.display = 'block';
    const { ok: sok, data: sdata } = await api.stats();
    if (sok) {
      document.getElementById('stat-users').textContent  = sdata.users.total;
      document.getElementById('stat-recent').textContent = sdata.documents.recent_7_days;
    }
  }
}

// ── Documents ─────────────────────────────────────────────────────────────────
async function loadDocuments() {
  document.getElementById('docs-loading').style.display = 'flex';
  document.getElementById('docs-table').style.display   = 'none';
  document.getElementById('docs-empty').style.display   = 'none';

  const { ok, data } = await api.listDocs();
  document.getElementById('docs-loading').style.display = 'none';

  if (!ok) { showToast('Failed to load documents', 'error'); return; }

  const docs = data.documents;
  if (docs.length === 0) {
    document.getElementById('docs-empty').style.display = 'block';
    return;
  }

  document.getElementById('docs-table').style.display = 'block';
  document.getElementById('docs-tbody').innerHTML = docs.map(d => `
    <tr>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <span class="file-icon">${fileIcon(d.original_name)}</span>
          <div>
            <div style="font-weight:600">${truncate(d.original_name, 30)}</div>
            <div class="mono" style="font-size:0.72rem;color:var(--text-muted)">${d.uuid.slice(0,8)}…</div>
          </div>
        </div>
      </td>
      <td class="mono">${formatSize(d.file_size)}</td>
      <td><span class="badge badge-green">${(d.file_type || '').toUpperCase().slice(0,8)}</span></td>
      <td>
        <div class="hash-display" onclick="copyToClipboard('${d.sha256_hash}')" title="${d.sha256_hash}">
          ${d.sha256_hash ? d.sha256_hash.slice(0, 16) + '…' : '—'}
        </div>
      </td>
      <td class="mono" style="font-size:0.8rem">${formatDate(d.uploaded_at)}</td>
      <td>${d.owner_username || user.username}</td>
      <td style="text-align:right">
        <button class="btn-icon" onclick="downloadDoc('${d.uuid}','${d.original_name}')" title="Download">⬇️</button>
        <button class="btn-icon" onclick="quickVerify('${d.uuid}')" title="Verify integrity">✅</button>
        <button class="btn-icon" onclick="deleteDoc('${d.uuid}','${d.original_name}')" title="Delete" style="color:var(--red)">🗑️</button>
      </td>
    </tr>
  `).join('');
}

async function downloadDoc(uuid, name) {
  showToast('Decrypting and downloading…', 'info');
  const url = api.downloadDoc(uuid);
  downloadBlob(url, name, api._token());
}

async function deleteDoc(uuid, name) {
  if (!confirm(`Delete "${name}"? This cannot be undone.`)) return;
  const { ok, data } = await api.deleteDoc(uuid);
  if (ok) {
    showToast('Document deleted', 'success');
    loadDocuments();
  } else {
    showToast(data.error || 'Delete failed', 'error');
  }
}

async function quickVerify(uuid) {
  showToast('Verifying integrity…', 'info');
  const { ok, data } = await api.verifyDoc(uuid);
  if (!ok) { showToast('Verification failed', 'error'); return; }
  const status = data.overall_status === 'VALID';
  showToast(status ? '✅ Document is authentic and unmodified' : '❌ Document may be tampered!', status ? 'success' : 'error');
}

// ── Upload ────────────────────────────────────────────────────────────────────
let selectedFile = null;

function triggerUpload() {
  document.getElementById('file-input').click();
}

function handleFileSelected(file) {
  if (!file) return;
  selectedFile = file;
  document.getElementById('preview-icon').textContent = fileIcon(file.name);
  document.getElementById('preview-name').textContent = file.name;
  document.getElementById('preview-size').textContent = formatSize(file.size) + ' · ' + (file.type || 'unknown type');
  document.getElementById('file-preview').style.display = 'block';
  document.getElementById('upload-btn').disabled = false;
  document.getElementById('upload-error').className   = 'error-msg';
  document.getElementById('upload-success').className = 'success-msg';
  document.getElementById('upload-result').style.display = 'none';
}

function clearFile() {
  selectedFile = null;
  document.getElementById('file-input').value = '';
  document.getElementById('file-preview').style.display = 'none';
  document.getElementById('upload-btn').disabled = true;
}

// Drag and drop
const uploadZone = document.getElementById('upload-zone');
if (uploadZone) {
  uploadZone.addEventListener('dragover', e => { e.preventDefault(); uploadZone.classList.add('dragover'); });
  uploadZone.addEventListener('dragleave', () => uploadZone.classList.remove('dragover'));
  uploadZone.addEventListener('drop', e => {
    e.preventDefault();
    uploadZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelected(file);
  });
}

async function uploadFile() {
  if (!selectedFile) return;

  const btn = document.getElementById('upload-btn');
  const errEl = document.getElementById('upload-error');
  const sucEl = document.getElementById('upload-success');
  errEl.className = 'error-msg';
  sucEl.className = 'success-msg';

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Encrypting & Uploading…';

  const fd = new FormData();
  fd.append('file', selectedFile);

  const { ok, data } = await api.uploadDoc(fd);

  btn.disabled = false;
  btn.innerHTML = '<span>🔒 Encrypt & Upload</span>';

  if (!ok) {
    errEl.textContent = data.error || 'Upload failed';
    errEl.className = 'error-msg show';
    return;
  }

  sucEl.textContent = 'Document encrypted and uploaded successfully!';
  sucEl.className = 'success-msg show';

  const doc = data.document;
  document.getElementById('upload-result').style.display = 'block';
  document.getElementById('upload-result').innerHTML = `
    <div class="card" style="background:var(--bg-input)">
      <h3 style="margin-bottom:12px;color:var(--green)">✅ Upload Complete</h3>
      <div style="display:grid;gap:8px;font-size:0.88rem">
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--text-muted)">File</span>
          <strong>${doc.original_name}</strong>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--text-muted)">Size</span>
          <span class="mono">${formatSize(doc.file_size)}</span>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--text-muted)">Encrypted</span>
          <span class="badge badge-green">AES-256-GCM ✓</span>
        </div>
        <div style="display:flex;justify-content:space-between">
          <span style="color:var(--text-muted)">Signed</span>
          <span class="badge badge-green">RSA-2048 ✓</span>
        </div>
        <div>
          <div style="color:var(--text-muted);margin-bottom:4px">SHA-256 Hash</div>
          <div class="hash-display" style="max-width:100%;white-space:normal;word-break:break-all;font-size:0.7rem;cursor:pointer" onclick="copyToClipboard('${doc.sha256_hash}')">${doc.sha256_hash}</div>
        </div>
      </div>
    </div>`;

  clearFile();
  showToast('Document encrypted and stored securely!', 'success');
}

// ── Verify ────────────────────────────────────────────────────────────────────
async function loadVerifySelect() {
  const { ok, data } = await api.listDocs();
  if (!ok) return;
  const sel = document.getElementById('verify-doc-select');
  sel.innerHTML = '<option value="">— Select a document —</option>';
  data.documents.forEach(d => {
    const opt = document.createElement('option');
    opt.value = d.uuid;
    opt.textContent = truncate(d.original_name, 50) + ' (' + formatDate(d.uploaded_at) + ')';
    sel.appendChild(opt);
  });
}

async function verifyDocument() {
  const uuid = document.getElementById('verify-doc-select').value;
  if (!uuid) { showToast('Please select a document', 'error'); return; }

  const resultEl = document.getElementById('verify-result');
  resultEl.className = 'verify-result show';
  resultEl.innerHTML = '<div class="spinner" style="margin:0 auto"></div>';

  const textVal = (document.getElementById('verify-candidate-text') || {}).value || '';
  const fileInput = document.getElementById('verify-candidate-file');
  let verifyBody = null;

  if (fileInput && fileInput.files && fileInput.files[0]) {
    const buf = await fileInput.files[0].arrayBuffer();
    verifyBody = { candidate_plaintext_b64: uint8ToBase64(new Uint8Array(buf)) };
  } else if (textVal.length > 0) {
    verifyBody = { candidate_text: textVal };
  }

  const { ok, data } = verifyBody
    ? await api.verifyDoc(uuid, verifyBody)
    : await api.verifyDoc(uuid);

  if (!ok) {
    resultEl.className = 'verify-result show invalid';
    resultEl.innerHTML = `<h3 class="red">❌ Verification Error</h3><p>${data.error || 'Unknown error'}</p>`;
    return;
  }

  const valid = data.overall_status === 'VALID';
  resultEl.className = `verify-result show ${valid ? 'valid' : 'invalid'}`;
  const cand = data.candidate_provided;
  const candOk = data.candidate_integrity_check;
  let candBlock = '';
  if (cand) {
    const pass = candOk === true;
    candBlock = `
    <div class="verify-check" style="margin-top:12px;padding-top:12px;border-top:1px solid var(--border)">
      <span>${pass ? '✅' : '❌'}</span>
      <span><strong>Your modified / pasted content</strong> vs recorded hash: <strong>${pass ? 'MATCH (same bytes as upload)' : 'NO MATCH (tampered or different file)'}</strong></span>
    </div>
    <div style="margin-top:8px;font-size:0.78rem;color:var(--text-muted)">Candidate SHA-256</div>
    <div class="hash-display" style="max-width:100%;white-space:normal;word-break:break-all;font-size:0.7rem" onclick="copyToClipboard('${data.candidate_hash || ''}')">${data.candidate_hash || '—'}</div>`;
  }

  resultEl.innerHTML = `
    <h3 class="${valid ? 'green' : 'red'}">${valid ? '✅ Vault copy is authentic' : '❌ Vault copy may be tampered'}</h3>
    <p style="margin-bottom:16px;font-size:0.88rem">${data.original_name}</p>
    <div class="verify-check"><span>${data.integrity_check ? '✅' : '❌'}</span><span>Vault SHA-256 (decrypt → hash): <strong>${data.integrity_check ? 'PASS' : 'FAIL'}</strong></span></div>
    <div class="verify-check"><span>${data.signature_check ? '✅' : '❌'}</span><span>RSA-2048 digital signature: <strong>${data.signature_check ? 'VALID' : 'INVALID'}</strong></span></div>
    <div class="verify-check"><span>🔒</span><span>Encryption: <strong>AES-256-GCM</strong></span></div>
    <div style="margin-top:12px">
      <div style="font-size:0.78rem;color:var(--text-muted);margin-bottom:4px">Stored SHA-256 (at upload)</div>
      <div class="hash-display" style="max-width:100%;white-space:normal;word-break:break-all;font-size:0.7rem" onclick="copyToClipboard('${data.stored_hash}')">${data.stored_hash}</div>
    </div>
    ${data.vault_current_hash ? `<div style="margin-top:10px">
      <div style="font-size:0.78rem;color:var(--text-muted);margin-bottom:4px">Current vault plaintext hash</div>
      <div class="hash-display" style="max-width:100%;white-space:normal;word-break:break-all;font-size:0.7rem" onclick="copyToClipboard('${data.vault_current_hash}')">${data.vault_current_hash}</div>
    </div>` : ''}
    ${candBlock}`;
}

// ── Users (admin) ─────────────────────────────────────────────────────────────
async function loadUsers() {
  if (user.role !== 'admin' && user.role !== 'manager') return;

  document.getElementById('users-loading').style.display = 'flex';
  document.getElementById('users-table').style.display   = 'none';

  const { ok, data } = await api.listUsers();
  document.getElementById('users-loading').style.display = 'none';
  if (!ok) { showToast('Failed to load users', 'error'); return; }

  document.getElementById('users-table').style.display = 'block';
  document.getElementById('users-tbody').innerHTML = data.users.map(u => `
    <tr>
      <td>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="avatar" style="width:30px;height:30px;font-size:0.75rem">${u.username[0].toUpperCase()}</div>
          <strong>${u.username}</strong>
        </div>
      </td>
      <td class="mono" style="font-size:0.8rem">${u.email}</td>
      <td><span class="badge badge-${u.role === 'admin' ? 'admin' : u.role === 'manager' ? 'manager' : 'user'}">${u.role}</span></td>
      <td><span class="badge ${u.totp_enabled ? 'badge-green' : 'badge-red'}">${u.totp_enabled ? '✓ On' : '✗ Off'}</span></td>
      <td>${u.oauth_provider ? `<span class="badge badge-yellow">${u.oauth_provider}</span>` : '—'}</td>
      <td><span class="badge ${u.is_active ? 'badge-green' : 'badge-red'}">${u.is_active ? 'Active' : 'Inactive'}</span></td>
      <td class="mono" style="font-size:0.78rem">${formatDate(u.created_at)}</td>
      <td style="text-align:right">
        ${user.role === 'admin' ? `
          <button class="btn-icon" onclick="openRoleModal(${u.id},'${u.username}')" title="Change role">🎭</button>
          <button class="btn-icon" onclick="toggleUserStatus(${u.id},${u.is_active},'${u.username}')" title="${u.is_active ? 'Deactivate' : 'Activate'}">
            ${u.is_active ? '🚫' : '✅'}
          </button>` : '—'}
      </td>
    </tr>
  `).join('');
}

function openRoleModal(id, username) {
  document.getElementById('role-modal-uid').value        = id;
  document.getElementById('role-modal-user').textContent = username;
  document.getElementById('role-modal').classList.add('show');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('show');
}

async function setRole(role) {
  const id = document.getElementById('role-modal-uid').value;
  const { ok, data } = await api.updateRole(id, { role });
  closeModal('role-modal');
  if (ok) { showToast('Role updated to ' + role, 'success'); loadUsers(); }
  else showToast(data.error || 'Failed', 'error');
}

async function toggleUserStatus(id, currentActive, username) {
  const newStatus = !currentActive;
  if (!confirm(`${newStatus ? 'Activate' : 'Deactivate'} user "${username}"?`)) return;
  const { ok, data } = await api.updateStatus(id, { is_active: newStatus });
  if (ok) { showToast('User ' + (newStatus ? 'activated' : 'deactivated'), 'success'); loadUsers(); }
  else showToast(data.error || 'Failed', 'error');
}

// ── Audit Logs ────────────────────────────────────────────────────────────────
async function loadAuditLogs() {
  document.getElementById('audit-loading').style.display = 'flex';
  document.getElementById('audit-table').style.display   = 'none';

  const { ok, data } = await api.auditLogs();
  document.getElementById('audit-loading').style.display = 'none';
  if (!ok) { showToast('Failed to load audit logs', 'error'); return; }

  document.getElementById('audit-table').style.display = 'block';

  const actionColors = {
    LOGIN: 'badge-green', LOGOUT: 'badge-user',
    REGISTER: 'badge-yellow', UPLOAD: 'badge-green',
    DOWNLOAD: 'badge-user', DELETE: 'badge-red',
    VERIFY: 'badge-yellow', CHANGE_ROLE: 'badge-admin',
    LOGIN_FAIL: 'badge-red', '2FA_ENABLED': 'badge-green',
    '2FA_DISABLED': 'badge-red', '2FA_FAIL': 'badge-red',
    CHANGE_PASSWORD: 'badge-yellow',
  };

  document.getElementById('audit-tbody').innerHTML = data.logs.map(l => `
    <tr>
      <td class="mono" style="font-size:0.78rem;white-space:nowrap">${formatDate(l.timestamp)}</td>
      <td><strong>${l.username || 'System'}</strong></td>
      <td><span class="badge ${actionColors[l.action] || 'badge-user'}">${l.action}</span></td>
      <td style="font-size:0.85rem">${l.target || '—'}</td>
      <td class="mono" style="font-size:0.78rem">${l.ip_address || '—'}</td>
    </tr>
  `).join('');
}

// ── Security Settings ─────────────────────────────────────────────────────────
async function loadSecurityPage() {
  const { ok, data } = await api.me();
  if (!ok) return;

  // 2FA is MANDATORY for all users - always show as enabled
  document.getElementById('totp-enabled-ui').style.display  = 'block';
  document.getElementById('totp-disabled-ui').style.display = 'none';
  document.getElementById('totp-setup-ui').style.display    = 'none';
}

async function changePassword() {
  const oldPw  = document.getElementById('old-pw').value;
  const newPw  = document.getElementById('new-pw').value;
  const newPw2 = document.getElementById('new-pw2').value;
  const errEl  = document.getElementById('pw-error');
  errEl.className = 'error-msg';

  if (newPw !== newPw2) {
    errEl.textContent = 'New passwords do not match';
    errEl.className = 'error-msg show';
    return;
  }

  const { ok, data } = await api.changePw({ old_password: oldPw, new_password: newPw });
  if (ok) {
    showToast('Password updated successfully!', 'success');
    document.getElementById('old-pw').value  = '';
    document.getElementById('new-pw').value  = '';
    document.getElementById('new-pw2').value = '';
  } else {
    errEl.textContent = data.error || 'Failed to update password';
    errEl.className = 'error-msg show';
  }
}

async function setup2fa() {
  document.getElementById('totp-disabled-ui').style.display = 'none';
  document.getElementById('totp-setup-ui').style.display    = 'block';
  document.getElementById('totp-secret-display').textContent = 'Loading…';

  const { ok, data } = await api.setup2fa();
  if (!ok) { showToast('Failed to set up 2FA', 'error'); return; }

  document.getElementById('totp-secret-display').textContent = data.secret;
  document.getElementById('totp-uri-display').textContent    = data.uri;
}

function cancelSetup2fa() {
  document.getElementById('totp-disabled-ui').style.display = 'block';
  document.getElementById('totp-setup-ui').style.display    = 'none';
}

async function confirmEnable2fa() {
  const code  = document.getElementById('totp-confirm-code').value.trim();
  const errEl = document.getElementById('totp-error');
  errEl.className = 'error-msg';

  if (code.length !== 6) {
    errEl.textContent = 'Please enter the 6-digit code from your authenticator';
    errEl.className = 'error-msg show';
    return;
  }

  const { ok, data } = await api.enable2fa({ code });
  if (ok) {
    showToast('2FA enabled successfully! 🛡️', 'success');
    loadSecurityPage();
    // Update sidebar
    const u = getUser();
    u.totp_enabled = true;
    localStorage.setItem('user', JSON.stringify(u));
  } else {
    errEl.textContent = data.error || 'Invalid code';
    errEl.className = 'error-msg show';
  }
}

// 2FA is MANDATORY and cannot be disabled
// This function is disabled as 2FA is a requirement for all users

// ── Close modal on overlay click ──────────────────────────────────────────────
document.querySelectorAll('.modal-overlay').forEach(overlay => {
  overlay.addEventListener('click', e => {
    if (e.target === overlay) overlay.classList.remove('show');
  });
});
