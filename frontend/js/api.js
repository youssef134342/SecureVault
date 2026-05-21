/**
 * API client — all backend calls go through here.
 * Automatically attaches JWT bearer token.
 */

const API_BASE = window.location.origin + '/api';

const api = {
  _token: () => localStorage.getItem('access_token'),

  _headers(extra = {}) {
    const h = { 'Content-Type': 'application/json', ...extra };
    const t = this._token();
    if (t) h['Authorization'] = 'Bearer ' + t;
    return h;
  },

  async _req(method, path, body, isFormData = false) {
    const opts = {
      method,
      headers: isFormData
        ? { Authorization: 'Bearer ' + this._token() }
        : this._headers()
    };
    if (body && !isFormData) opts.body = JSON.stringify(body);
    if (body && isFormData) opts.body = body;

    try {
      const res = await fetch(API_BASE + path, opts);
      const data = await res.json().catch(() => ({ error: 'Invalid server response' }));
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      return { ok: false, status: 0, data: { error: 'Network error: ' + err.message } };
    }
  },

  get:    (path)         => api._req('GET',    path),
  post:   (path, body)   => api._req('POST',   path, body),
  put:    (path, body)   => api._req('PUT',    path, body),
  delete: (path)         => api._req('DELETE', path),
  upload: (path, formData) => api._req('POST', path, formData, true),

  // Auth
  login:          (d)    => api.post('/auth/login', d),
  register:       (d)    => api.post('/auth/register', d),
  logout:         ()     => api.post('/auth/logout'),
  me:             ()     => api.get('/auth/me'),
  changePw:       (d)    => api.post('/auth/change-password', d),
  setup2fa:       ()     => api.post('/auth/2fa/setup'),
  enable2fa:      (d)    => api.post('/auth/2fa/enable', d),
  disable2fa:     (d)    => api.post('/auth/2fa/disable', d),

  // Documents
  listDocs:       ()     => api.get('/documents/'),
  uploadDoc:      (fd)   => api.upload('/documents/upload', fd),
  getDoc:         (uuid) => api.get(`/documents/${uuid}`),
  downloadDoc:    (uuid) => API_BASE + `/documents/${uuid}/download`,
  verifyDoc:      (uuid, body) => {
    const hasCandidate = body && (
      (body.candidate_plaintext_b64 && String(body.candidate_plaintext_b64).trim() !== '') ||
      (body.candidate_text != null && String(body.candidate_text).length > 0)
    );
    if (hasCandidate) return api.post(`/documents/${uuid}/verify`, body);
    return api.get(`/documents/${uuid}/verify`);
  },
  deleteDoc:      (uuid) => api.delete(`/documents/${uuid}`),

  // Admin
  listUsers:      ()     => api.get('/admin/users'),
  updateRole:     (id,d) => api.put(`/admin/users/${id}/role`, d),
  updateStatus:   (id,d) => api.put(`/admin/users/${id}/status`, d),
  deleteUser:     (id)   => api.delete(`/admin/users/${id}`),
  auditLogs:      ()     => api.get('/admin/audit-logs'),
  stats:          ()     => api.get('/admin/stats'),

  // OAuth info
  oauthProviders: ()     => api.get('/oauth/providers'),
};

// ── Auth helpers ──────────────────────────────────────────────────────────────

function saveAuth(data) {
  localStorage.setItem('access_token', data.access_token);
  localStorage.setItem('refresh_token', data.refresh_token);
  localStorage.setItem('user', JSON.stringify(data.user));
}

function getUser() {
  try { return JSON.parse(localStorage.getItem('user')); } catch { return null; }
}

function clearAuth() {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
  localStorage.removeItem('user');
}

function isLoggedIn() {
  return !!localStorage.getItem('access_token');
}

function requireAuth() {
  if (!isLoggedIn()) {
    window.location.href = '/index.html';
  }
}

function requireRole(...roles) {
  const user = getUser();
  if (!user || !roles.includes(user.role)) {
    showToast('Access denied: insufficient permissions', 'error');
    return false;
  }
  return true;
}

// ── Toast ─────────────────────────────────────────────────────────────────────

function showToast(msg, type = 'info') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = `toast ${type} show`;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.className = 'toast'; }, 3500);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / 1048576).toFixed(1) + ' MB';
}

function formatDate(str) {
  if (!str) return '—';
  return new Date(str).toLocaleString();
}

function fileIcon(name) {
  const ext = (name || '').split('.').pop().toLowerCase();
  const icons = {
    pdf: '📄', docx: '📝', doc: '📝', txt: '📃',
    png: '🖼️', jpg: '🖼️', jpeg: '🖼️',
    xlsx: '📊', csv: '📊', pptx: '📑',
    default: '📁'
  };
  return icons[ext] || icons.default;
}

function truncate(str, n = 40) {
  return str && str.length > n ? str.slice(0, n) + '…' : (str || '');
}

function togglePw(id, btn) {
  const inp = document.getElementById(id);
  if (!inp) return;
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}

function checkPwStrength(pw) {
  const fill = document.getElementById('pw-strength-fill');
  const hint = document.getElementById('pw-hint');
  if (!fill) return;

  let score = 0;
  if (pw.length >= 8) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[a-z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(pw)) score++;

  const colors = ['#ef4444', '#f59e0b', '#f59e0b', '#22c55e', '#22c55e'];
  const labels = ['Very weak', 'Weak', 'Fair', 'Strong', 'Very strong'];
  fill.style.width = (score * 20) + '%';
  fill.style.background = colors[score - 1] || '#ef4444';
  if (hint) hint.textContent = pw ? labels[score - 1] || 'Very weak' : '';
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast('Copied to clipboard', 'success');
  }).catch(() => {
    showToast('Copy failed', 'error');
  });
}

function downloadBlob(url, filename, token) {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'document';
  // Use fetch for authenticated download
  fetch(url, { headers: { Authorization: 'Bearer ' + token } })
    .then(r => r.blob())
    .then(blob => {
      const blobUrl = URL.createObjectURL(blob);
      a.href = blobUrl;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(blobUrl);
    })
    .catch(() => showToast('Download failed', 'error'));
}
