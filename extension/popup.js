/**
 * Popup UI Controller - PasskeyVault management interface.
 *
 * Handles vault creation, unlock, passkey registration, credential management.
 * Communicates with the background service worker via chrome.runtime messages.
 */

'use strict';

(() => {
  // --- DOM References ---
  const el = {
    lockIndicator: document.getElementById('lockIndicator'),
    statusMessage: document.getElementById('statusMessage'),
    setupView: document.getElementById('setupView'),
    unlockView: document.getElementById('unlockView'),
    dashboardView: document.getElementById('dashboardView'),
    // Setup
    setupPin: document.getElementById('setupPin'),
    setupPinConfirm: document.getElementById('setupPinConfirm'),
    createVaultBtn: document.getElementById('createVaultBtn'),
    // Unlock
    unlockPin: document.getElementById('unlockPin'),
    unlockBtn: document.getElementById('unlockBtn'),
    // Dashboard
    statPasskeys: document.getElementById('statPasskeys'),
    statUsers: document.getElementById('statUsers'),
    passkeyList: document.getElementById('passkeyList'),
    emptyState: document.getElementById('emptyState'),
    showRegisterBtn: document.getElementById('showRegisterBtn'),
    registerForm: document.getElementById('registerForm'),
    regDisplayName: document.getElementById('regDisplayName'),
    regUpn: document.getElementById('regUpn'),
    regRpId: document.getElementById('regRpId'),
    cancelRegisterBtn: document.getElementById('cancelRegisterBtn'),
    registerBtn: document.getElementById('registerBtn'),
    // Credentials
    toggleCredentialForm: document.getElementById('toggleCredentialForm'),
    credentialForm: document.getElementById('credentialForm'),
    credDomain: document.getElementById('credDomain'),
    credUsername: document.getElementById('credUsername'),
    credPassword: document.getElementById('credPassword'),
    saveCredential: document.getElementById('saveCredential'),
    cancelCredential: document.getElementById('cancelCredential'),
    credentialList: document.getElementById('credentialList'),
    credentialEmptyState: document.getElementById('credentialEmptyState'),
    // Actions
    lockVault: document.getElementById('lockVault'),
    resetVault: document.getElementById('resetVault')
  };

  // --- Initialization ---

  init();

  async function init() {
    bindEvents();
    await determineView();
  }

  function bindEvents() {
    // Setup view
    el.setupPin.addEventListener('input', validateSetupForm);
    el.setupPinConfirm.addEventListener('input', validateSetupForm);
    el.createVaultBtn.addEventListener('click', handleCreateVault);
    el.setupPin.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') el.setupPinConfirm.focus();
    });
    el.setupPinConfirm.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !el.createVaultBtn.disabled) handleCreateVault();
    });

    // Unlock view
    el.unlockBtn.addEventListener('click', handleUnlock);
    el.unlockPin.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') handleUnlock();
    });

    // Dashboard - Passkeys
    el.showRegisterBtn.addEventListener('click', toggleRegisterForm);
    el.cancelRegisterBtn.addEventListener('click', toggleRegisterForm);
    el.registerBtn.addEventListener('click', handleRegisterPasskey);

    // Dashboard - Credentials
    el.toggleCredentialForm.addEventListener('click', toggleCredForm);
    el.cancelCredential.addEventListener('click', toggleCredForm);
    el.saveCredential.addEventListener('click', handleSaveCredential);

    // Dashboard - Actions
    el.lockVault.addEventListener('click', handleLock);
    el.resetVault.addEventListener('click', handleDestroy);
  }

  // --- View Management ---

  async function determineView() {
    const { exists } = await sendMessage('vault.exists');

    if (!exists) {
      showView('setup');
      return;
    }

    const { unlocked } = await sendMessage('vault.isUnlocked');
    if (unlocked) {
      showView('dashboard');
      await refreshDashboard();
    } else {
      showView('unlock');
      el.unlockPin.focus();
    }
  }

  function showView(view) {
    el.setupView.classList.remove('active');
    el.unlockView.classList.remove('active');
    el.dashboardView.classList.remove('active');
    clearStatus();

    switch (view) {
      case 'setup':
        el.setupView.classList.add('active');
        el.lockIndicator.textContent = 'No Vault';
        el.lockIndicator.className = 'lock-indicator locked';
        el.setupPin.focus();
        break;
      case 'unlock':
        el.unlockView.classList.add('active');
        el.lockIndicator.textContent = 'Locked';
        el.lockIndicator.className = 'lock-indicator locked';
        el.unlockPin.focus();
        break;
      case 'dashboard':
        el.dashboardView.classList.add('active');
        el.lockIndicator.textContent = 'Unlocked';
        el.lockIndicator.className = 'lock-indicator unlocked';
        break;
    }
  }

  // --- Status Messages ---

  function showStatus(type, text) {
    el.statusMessage.textContent = text;
    el.statusMessage.className = `status visible ${type}`;
    if (type === 'success') {
      setTimeout(clearStatus, 3000);
    }
  }

  function clearStatus() {
    el.statusMessage.className = 'status';
    el.statusMessage.textContent = '';
  }

  // --- Vault Creation ---

  function validateSetupForm() {
    const pin = el.setupPin.value;
    const confirm = el.setupPinConfirm.value;
    el.createVaultBtn.disabled = !(pin.length >= 4 && pin === confirm);
  }

  async function handleCreateVault() {
    const pin = el.setupPin.value;
    if (pin.length < 4) {
      showStatus('error', 'PIN must be at least 4 characters');
      return;
    }
    if (pin !== el.setupPinConfirm.value) {
      showStatus('error', 'PINs do not match');
      return;
    }

    el.createVaultBtn.disabled = true;
    try {
      const result = await sendMessage('vault.create', { pin });
      if (result.error) {
        showStatus('error', result.error);
        return;
      }
      showStatus('success', 'Vault created successfully');
      showView('dashboard');
      await refreshDashboard();
    } catch (err) {
      showStatus('error', err.message);
    } finally {
      el.createVaultBtn.disabled = false;
      el.setupPin.value = '';
      el.setupPinConfirm.value = '';
    }
  }

  // --- Vault Unlock ---

  async function handleUnlock() {
    const pin = el.unlockPin.value;
    if (!pin) {
      showStatus('error', 'Enter your vault PIN');
      return;
    }

    el.unlockBtn.disabled = true;
    try {
      const result = await sendMessage('vault.unlock', { pin });
      if (result.error) {
        showStatus('error', result.error);
        return;
      }
      if (!result.success) {
        showStatus('error', 'Incorrect PIN');
        el.unlockPin.value = '';
        el.unlockPin.focus();
        return;
      }
      showView('dashboard');
      await refreshDashboard();
    } catch (err) {
      showStatus('error', err.message);
    } finally {
      el.unlockBtn.disabled = false;
      el.unlockPin.value = '';
    }
  }

  // --- Dashboard ---

  async function refreshDashboard() {
    try {
      const { summary } = await sendMessage('vault.summary');
      if (!summary) return;

      el.statPasskeys.textContent = summary.passkeyCount;
      el.statUsers.textContent = summary.userCount;

      renderPasskeyList(summary.passkeys);
    } catch {
      showStatus('error', 'Failed to load vault data');
    }

    await refreshCredentials();
  }

  function renderPasskeyList(passkeys) {
    el.passkeyList.innerHTML = '';

    if (!passkeys || passkeys.length === 0) {
      el.emptyState.style.display = 'block';
      return;
    }

    el.emptyState.style.display = 'none';

    for (const pk of passkeys) {
      const li = document.createElement('li');
      li.className = 'passkey-item';

      const lastUsed = pk.lastUsed
        ? new Date(pk.lastUsed).toLocaleDateString()
        : 'Never';

      li.innerHTML = `
        <div class="passkey-icon">&#128273;</div>
        <div class="passkey-details">
          <div class="passkey-rp">${escapeHtml(pk.rpName || pk.rpId)}</div>
          <div class="passkey-meta">
            Signs: ${pk.signCount} &middot; Last used: ${lastUsed}
          </div>
        </div>
        <div class="passkey-actions">
          <button class="delete-btn" data-credential-id="${escapeHtml(pk.credentialId)}" title="Delete passkey">&#10005;</button>
        </div>
      `;

      const deleteBtn = li.querySelector('.delete-btn');
      deleteBtn.addEventListener('click', () => handleDeletePasskey(pk.credentialId));

      el.passkeyList.appendChild(li);
    }
  }

  // --- Passkey Registration ---

  function toggleRegisterForm() {
    const isVisible = el.registerForm.style.display !== 'none';
    el.registerForm.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) el.regDisplayName.focus();
  }

  async function handleRegisterPasskey() {
    const displayName = el.regDisplayName.value.trim();
    const upn = el.regUpn.value.trim();
    const rpId = el.regRpId.value.trim();

    if (!displayName || !upn) {
      showStatus('error', 'Display name and UPN are required');
      return;
    }

    el.registerBtn.disabled = true;
    try {
      // Add user first
      const { userId, error: userError } = await sendMessage('user.add', {
        displayName,
        entraUpn: upn
      });
      if (userError) {
        showStatus('error', userError);
        return;
      }

      // Register passkey
      const { registration, error: regError } = await sendMessage('passkey.register', {
        rpId: rpId || 'login.microsoft.com',
        rpName: 'Microsoft Entra ID',
        userId,
        userName: displayName
      });

      if (regError) {
        showStatus('error', regError);
        return;
      }

      showStatus('success', 'Passkey registered successfully');
      el.registerForm.style.display = 'none';
      el.regDisplayName.value = '';
      el.regUpn.value = '';
      await refreshDashboard();
    } catch (err) {
      showStatus('error', err.message);
    } finally {
      el.registerBtn.disabled = false;
    }
  }

  // --- Passkey Deletion ---

  async function handleDeletePasskey(credentialId) {
    if (!confirm('Delete this passkey? This cannot be undone.')) return;

    try {
      const { deleted, error } = await sendMessage('passkey.delete', { credentialId });
      if (error) {
        showStatus('error', error);
        return;
      }
      if (deleted) {
        showStatus('success', 'Passkey deleted');
        await refreshDashboard();
      }
    } catch (err) {
      showStatus('error', err.message);
    }
  }

  // --- Credential Management ---

  function toggleCredForm() {
    const isVisible = el.credentialForm.style.display !== 'none';
    el.credentialForm.style.display = isVisible ? 'none' : 'block';
    if (!isVisible) el.credDomain.focus();
  }

  async function handleSaveCredential() {
    const domain = el.credDomain.value.trim();
    const username = el.credUsername.value.trim();
    const password = el.credPassword.value;

    if (!domain || !username || !password) {
      showStatus('error', 'Domain, username, and password are required');
      return;
    }

    el.saveCredential.disabled = true;
    try {
      const { id, error } = await sendMessage('credential.add', { domain, username, password });
      if (error) {
        showStatus('error', error);
        return;
      }
      showStatus('success', 'Credential saved');
      el.credentialForm.style.display = 'none';
      el.credDomain.value = '';
      el.credUsername.value = '';
      el.credPassword.value = '';
      await refreshCredentials();
    } catch (err) {
      showStatus('error', err.message);
    } finally {
      el.saveCredential.disabled = false;
    }
  }

  async function refreshCredentials() {
    try {
      const { credentials, error } = await sendMessage('credential.list');
      if (error) return;
      renderCredentialList(credentials || []);
    } catch {
      // Silently fail - credentials may not be supported on older vaults until re-saved
    }
  }

  function renderCredentialList(credentials) {
    el.credentialList.innerHTML = '';

    if (!credentials || credentials.length === 0) {
      el.credentialEmptyState.style.display = 'block';
      return;
    }

    el.credentialEmptyState.style.display = 'none';

    for (const cred of credentials) {
      const item = document.createElement('div');
      item.className = 'credential-item';

      item.innerHTML = `
        <div class="credential-icon">&#128274;</div>
        <div class="credential-details">
          <div class="credential-domain">${escapeHtml(cred.domain)}</div>
          <div class="credential-user">${escapeHtml(cred.username)}</div>
        </div>
        <div class="credential-actions">
          <button class="copy-btn" title="Copy password">&#128203;</button>
          <button class="delete-btn" title="Delete credential">&#10005;</button>
        </div>
      `;

      const copyBtn = item.querySelector('.copy-btn');
      copyBtn.addEventListener('click', () => handleCopyPassword(cred.id));

      const deleteBtn = item.querySelector('.delete-btn');
      deleteBtn.addEventListener('click', () => handleDeleteCredential(cred.id));

      el.credentialList.appendChild(item);
    }
  }

  async function handleCopyPassword(id) {
    try {
      const { password, error } = await sendMessage('credential.getPassword', { id });
      if (error) {
        showStatus('error', error);
        return;
      }
      await navigator.clipboard.writeText(password);
      showStatus('success', 'Password copied to clipboard');
    } catch (err) {
      showStatus('error', err.message);
    }
  }

  async function handleDeleteCredential(id) {
    if (!confirm('Delete this credential? This cannot be undone.')) return;

    try {
      const { deleted, error } = await sendMessage('credential.delete', { id });
      if (error) {
        showStatus('error', error);
        return;
      }
      if (deleted) {
        showStatus('success', 'Credential deleted');
        await refreshCredentials();
      }
    } catch (err) {
      showStatus('error', err.message);
    }
  }

  // --- Lock / Destroy ---

  async function handleLock() {
    await sendMessage('vault.lock');
    showView('unlock');
  }

  async function handleDestroy() {
    if (!confirm('DESTROY the entire vault? All passkeys will be permanently deleted.')) return;
    if (!confirm('Are you absolutely sure? This is irreversible.')) return;

    try {
      await sendMessage('vault.destroy');
      showStatus('info', 'Vault destroyed');
      showView('setup');
    } catch (err) {
      showStatus('error', err.message);
    }
  }

  // --- Messaging ---

  function sendMessage(action, payload = {}) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action, payload }, (response) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
          return;
        }
        resolve(response || {});
      });
    });
  }

  // --- Utilities ---

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
})();
