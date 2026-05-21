// auth.js — login/register page logic

// Store 2FA setup data temporarily (modal / large QR)
let pendingTwoFaSetup = null;

function renderTotpQr(container, uri) {
  container.innerHTML = '';
  if (typeof QRCode === 'undefined') {
    container.innerHTML =
      '<p class="error-msg show" style="padding:12px">QR library failed to load. Refresh the page or enter the manual secret below.</p>';
    return;
  }
  try {
    new QRCode(container, {
      text: uri,
      width: 200,
      height: 200,
      colorDark: '#000000',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.H
    });
  } catch (err) {
    console.error(err);
    container.innerHTML =
      '<p class="error-msg show" style="padding:12px">Could not render QR. Use the manual secret below.</p>';
  }
}

// If already logged in, redirect to dashboard
if (isLoggedIn()) {
  window.location.href = '/pages/dashboard.html';
}

function showTab(tab) {
  document.getElementById('form-login').style.display    = tab === 'login'    ? 'block' : 'none';
  document.getElementById('form-register').style.display = tab === 'register' ? 'block' : 'none';
  document.getElementById('tab-login').classList.toggle('active',    tab === 'login');
  document.getElementById('tab-register').classList.toggle('active', tab === 'register');
}

async function handleLogin(e) {
  e.preventDefault();
  const errEl = document.getElementById('login-error');
  errEl.className = 'error-msg';

  const username  = document.getElementById('login-username').value.trim();
  const password  = document.getElementById('login-password').value;
  const totpCode  = document.getElementById('login-totp').value.trim();
  const btn       = document.getElementById('login-btn');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  const payload = { username, password };
  if (totpCode) payload.totp_code = totpCode;

  const { ok, data } = await api.login(payload);

  btn.disabled = false;
  btn.innerHTML = '<span>Sign In</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';

  // 2FA required — show inline QR + OTP field (same step as password; submit again with code)
  if (data.require_2fa) {
    const totpBlock = document.getElementById('totp-field');
    const qrEl = document.getElementById('login-qrcode');
    const secretEl = document.getElementById('login-totp-secret');
    totpBlock.style.display = 'block';
    document.getElementById('login-totp').value = '';
    document.getElementById('login-totp').focus();

    if (data.secret && data.uri) {
      secretEl.textContent = data.secret;
      renderTotpQr(qrEl, data.uri);
      pendingTwoFaSetup = { secret: data.secret, uri: data.uri, username };
    } else {
      secretEl.textContent = '—';
      qrEl.innerHTML = '<p class="error-msg show" style="padding:12px">Server did not return a TOTP URI. Contact support.</p>';
      pendingTwoFaSetup = null;
    }
    showToast('Scan the QR with your authenticator app, enter the 6-digit code, then click Sign In again.', 'info');
    return;
  }

  if (!ok) {
    errEl.textContent = data.error || 'Login failed';
    errEl.className = 'error-msg show';
    return;
  }

  saveAuth(data);
  showToast('Welcome back, ' + data.user.username + '!', 'success');
  setTimeout(() => { window.location.href = '/pages/dashboard.html'; }, 600);
}

async function handleRegister(e) {
  e.preventDefault();
  const errEl = document.getElementById('register-error');
  errEl.className = 'error-msg';

  const username = document.getElementById('reg-username').value.trim();
  const email    = document.getElementById('reg-email').value.trim();
  const password = document.getElementById('reg-password').value;
  const password2 = document.getElementById('reg-password2').value;
  const role     = document.getElementById('reg-role').value;
  const btn      = document.getElementById('register-btn');

  if (password !== password2) {
    errEl.textContent = 'Passwords do not match';
    errEl.className = 'error-msg show';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  const { ok, data } = await api.register({ username, email, password, role });

  btn.disabled = false;
  btn.innerHTML = '<span>Create Account</span><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>';

  if (!ok) {
    errEl.textContent = data.error || 'Registration failed';
    errEl.className = 'error-msg show';
    return;
  }

  showToast('Account created! Please sign in and set up 2FA.', 'success');
  showTab('login');
  document.getElementById('login-username').value = username;
}

function showQrModal() {
  if (!pendingTwoFaSetup) return;
  const modal = document.getElementById('2fa-setup-modal');
  modal.classList.add('show');
  document.getElementById('secret-display').textContent = pendingTwoFaSetup.secret;
  const qrContainer = document.getElementById('qrcode');
  renderTotpQr(qrContainer, pendingTwoFaSetup.uri);
  document.getElementById('2fa-confirm-code').value = '';
  const errEl = document.getElementById('qr-error');
  errEl.className = 'error-msg';
  errEl.textContent = '';
}

function closeQrModal() {
  const modal = document.getElementById('2fa-setup-modal');
  modal.classList.remove('show');
  showToast('Enter the code from your app in the Sign In form, then click Sign In.', 'info');
}

async function confirm2faSetup() {
  const code = document.getElementById('2fa-confirm-code').value.trim();
  const errEl = document.getElementById('qr-error');

  if (code.length !== 6 || !/^\d{6}$/.test(code)) {
    errEl.textContent = 'Please enter a valid 6-digit code';
    errEl.className = 'error-msg show';
    return;
  }

  errEl.className = 'error-msg';
  document.getElementById('login-totp').value = code;
  document.getElementById('2fa-setup-modal').classList.remove('show');
  document.getElementById('login-totp').focus();
  showToast('Code copied to Sign In. Click Sign In to finish.', 'success');
}

function oauthLogin(provider) {
  window.location.href = `/api/oauth/${provider}`;
}
