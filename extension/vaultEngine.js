/**
 * VaultEngine - Encrypted passkey vault managed entirely by the extension.
 *
 * Vault schema:
 *   vault
 *   ├── meta (version, createdAt, salt, lockTimeout)
 *   ├── users[]
 *   │   ├── userId
 *   │   ├── displayName
 *   │   └── entraUpn (User Principal Name)
 *   ├── passkeys[]
 *   │   ├── credentialId (base64url)
 *   │   ├── rpId
 *   │   ├── rpName
 *   │   ├── userId
 *   │   ├── encryptedPrivateKey {iv, data}
 *   │   ├── publicKey (base64)
 *   │   ├── signCount
 *   │   ├── createdAt
 *   │   └── lastUsed
 *   └── policies
 *       ├── lockTimeoutMs
 *       ├── maxFailedAttempts
 *       └── allowedRpIds[]
 *
 * The vault is stored encrypted in chrome.storage.local.
 * The decryption key is derived from a user PIN via PBKDF2 and held only in memory.
 * On lock or timeout the in-memory key is discarded.
 */

const VaultEngine = (() => {
  'use strict';

  const VAULT_STORAGE_KEY = 'pkv_vault_encrypted';
  const VAULT_META_KEY = 'pkv_vault_meta';
  const VAULT_VERSION = 1;
  const DEFAULT_LOCK_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
  const MAX_FAILED_ATTEMPTS = 5;

  /** @type {CryptoKey|null} In-memory vault key - never persisted. */
  let _vaultKey = null;
  /** @type {object|null} Decrypted vault data - only in memory. */
  let _vaultData = null;
  /** @type {number|null} Lock timer handle. */
  let _lockTimer = null;
  /** @type {number} Failed unlock attempts counter. */
  let _failedAttempts = 0;

  // --- Vault Lifecycle ---

  /**
   * Check whether a vault has been created.
   * @returns {Promise<boolean>}
   */
  async function exists() {
    const result = await chrome.storage.local.get(VAULT_META_KEY);
    return !!result[VAULT_META_KEY];
  }

  /**
   * Create a new vault protected by the given PIN.
   * @param {string} pin - User-chosen PIN.
   * @param {object} [options] - Optional initial vault policies.
   * @returns {Promise<void>}
   */
  async function create(pin, options = {}) {
    if (await exists()) {
      throw new Error('Vault already exists. Destroy it first to re-create.');
    }
    if (!pin || pin.length < 4) {
      throw new Error('PIN must be at least 4 characters');
    }

    const salt = CryptoEngine.getRandomBytes(CryptoEngine.SALT_LENGTH);
    const key = await CryptoEngine.deriveVaultKey(pin, salt);

    const vaultData = {
      version: VAULT_VERSION,
      users: [],
      passkeys: [],
      credentials: [],
      policies: {
        lockTimeoutMs: options.lockTimeoutMs || DEFAULT_LOCK_TIMEOUT_MS,
        maxFailedAttempts: options.maxFailedAttempts || MAX_FAILED_ATTEMPTS,
        allowedRpIds: options.allowedRpIds || [
          'login.microsoft.com',
          'login.microsoftonline.com'
        ]
      }
    };

    const meta = {
      version: VAULT_VERSION,
      createdAt: Date.now(),
      salt: CryptoEngine.uint8ToBase64(salt),
      lockTimeoutMs: vaultData.policies.lockTimeoutMs
    };

    const encrypted = await _encryptVault(key, vaultData);

    await chrome.storage.local.set({
      [VAULT_META_KEY]: meta,
      [VAULT_STORAGE_KEY]: encrypted
    });

    _vaultKey = key;
    _vaultData = vaultData;
    _failedAttempts = 0;
    _resetLockTimer();
  }

  /**
   * Unlock the vault using the user PIN.
   * @param {string} pin - Vault PIN.
   * @returns {Promise<boolean>} True if unlock succeeded.
   */
  async function unlock(pin) {
    if (_failedAttempts >= MAX_FAILED_ATTEMPTS) {
      throw new Error('Too many failed attempts. Vault is temporarily locked.');
    }

    const meta = await _getMeta();
    if (!meta) {
      throw new Error('No vault found');
    }

    const salt = CryptoEngine.base64ToUint8(meta.salt);
    const key = await CryptoEngine.deriveVaultKey(pin, salt);

    const stored = await chrome.storage.local.get(VAULT_STORAGE_KEY);
    const encrypted = stored[VAULT_STORAGE_KEY];
    if (!encrypted) {
      throw new Error('Vault data missing from storage');
    }

    try {
      _vaultData = await _decryptVault(key, encrypted);
      _vaultKey = key;
      _failedAttempts = 0;
      _resetLockTimer();
      return true;
    } catch {
      _failedAttempts++;
      _vaultKey = null;
      _vaultData = null;
      return false;
    }
  }

  /**
   * Lock the vault, wiping in-memory secrets.
   */
  function lock() {
    _vaultKey = null;
    _vaultData = null;
    if (_lockTimer !== null) {
      clearTimeout(_lockTimer);
      _lockTimer = null;
    }
  }

  /**
   * Check if vault is currently unlocked.
   * @returns {boolean}
   */
  function isUnlocked() {
    return _vaultKey !== null && _vaultData !== null;
  }

  /**
   * Destroy the vault entirely. Requires vault to be unlocked.
   * @returns {Promise<void>}
   */
  async function destroy() {
    await chrome.storage.local.remove([VAULT_META_KEY, VAULT_STORAGE_KEY]);
    lock();
    _failedAttempts = 0;
  }

  // --- User Management ---

  /**
   * Add a user identity to the vault.
   * @param {object} user - {displayName: string, entraUpn: string}
   * @returns {Promise<string>} The generated userId.
   */
  async function addUser(user) {
    _requireUnlocked();
    if (!user.displayName || !user.entraUpn) {
      throw new Error('displayName and entraUpn are required');
    }

    const existing = _vaultData.users.find(u => u.entraUpn === user.entraUpn);
    if (existing) {
      return existing.userId;
    }

    const userId = CryptoEngine.base64UrlEncode(CryptoEngine.getRandomBytes(16));
    _vaultData.users.push({
      userId,
      displayName: user.displayName,
      entraUpn: user.entraUpn,
      createdAt: Date.now()
    });

    await _persistVault();
    return userId;
  }

  /**
   * Get all users in the vault.
   * @returns {Array<object>}
   */
  function getUsers() {
    _requireUnlocked();
    return _vaultData.users.map(u => ({ ...u }));
  }

  /**
   * Find a user by UPN.
   * @param {string} upn - Entra UPN.
   * @returns {object|null}
   */
  function findUserByUpn(upn) {
    _requireUnlocked();
    const user = _vaultData.users.find(u => u.entraUpn === upn);
    return user ? { ...user } : null;
  }

  // --- Passkey Management ---

  /**
   * Store a new passkey in the vault.
   * The private key is encrypted before storage.
   * @param {object} passkey - Passkey data.
   * @param {string} passkey.rpId - Relying party ID.
   * @param {string} passkey.rpName - Relying party display name.
   * @param {string} passkey.userId - Associated user ID.
   * @param {ArrayBuffer} passkey.privateKey - PKCS8 private key (will be encrypted).
   * @param {ArrayBuffer} passkey.publicKey - SPKI public key.
   * @param {Uint8Array} [passkey.credentialId] - Credential ID (auto-generated if omitted).
   * @returns {Promise<string>} The credential ID (base64url).
   */
  async function storePasskey(passkey) {
    _requireUnlocked();

    if (!passkey.rpId || !passkey.userId || !passkey.privateKey || !passkey.publicKey) {
      throw new Error('rpId, userId, privateKey, and publicKey are required');
    }

    const credentialId = passkey.credentialId
      ? CryptoEngine.base64UrlEncode(passkey.credentialId)
      : CryptoEngine.base64UrlEncode(CryptoEngine.generateCredentialId());

    // Encrypt the private key
    const encryptedPrivateKey = await CryptoEngine.encryptString(
      _vaultKey,
      CryptoEngine.arrayBufferToBase64(passkey.privateKey)
    );

    const entry = {
      credentialId,
      rpId: passkey.rpId,
      rpName: passkey.rpName || passkey.rpId,
      userId: passkey.userId,
      encryptedPrivateKey,
      publicKey: CryptoEngine.arrayBufferToBase64(passkey.publicKey),
      signCount: 0,
      createdAt: Date.now(),
      lastUsed: null
    };

    // Replace existing passkey for same rpId+userId, or add new
    const existingIndex = _vaultData.passkeys.findIndex(
      p => p.rpId === passkey.rpId && p.userId === passkey.userId
    );
    if (existingIndex >= 0) {
      _vaultData.passkeys[existingIndex] = entry;
    } else {
      _vaultData.passkeys.push(entry);
    }

    await _persistVault();
    return credentialId;
  }

  /**
   * Retrieve a passkey by credential ID. Returns the entry with the
   * private key still encrypted.
   * @param {string} credentialId - Base64url credential ID.
   * @returns {object|null}
   */
  function getPasskey(credentialId) {
    _requireUnlocked();
    const entry = _vaultData.passkeys.find(p => p.credentialId === credentialId);
    return entry ? { ...entry } : null;
  }

  /**
   * Find passkeys matching a relying party ID.
   * @param {string} rpId - Relying party identifier.
   * @returns {Array<object>}
   */
  function getPasskeysByRpId(rpId) {
    _requireUnlocked();
    return _vaultData.passkeys
      .filter(p => p.rpId === rpId)
      .map(p => ({ ...p }));
  }

  /**
   * Find passkeys for a user.
   * @param {string} userId - User ID.
   * @returns {Array<object>}
   */
  function getPasskeysByUserId(userId) {
    _requireUnlocked();
    return _vaultData.passkeys
      .filter(p => p.userId === userId)
      .map(p => ({ ...p }));
  }

  /**
   * Decrypt and return the private key for a passkey.
   * The caller MUST zero out the returned buffer after use.
   * @param {string} credentialId - Base64url credential ID.
   * @returns {Promise<ArrayBuffer>} PKCS8 private key.
   */
  async function getDecryptedPrivateKey(credentialId) {
    _requireUnlocked();
    const entry = _vaultData.passkeys.find(p => p.credentialId === credentialId);
    if (!entry) {
      throw new Error('Passkey not found');
    }

    const privateKeyBase64 = await CryptoEngine.decryptString(
      _vaultKey,
      entry.encryptedPrivateKey
    );
    return CryptoEngine.base64ToArrayBuffer(privateKeyBase64);
  }

  /**
   * Increment the sign counter for a passkey.
   * @param {string} credentialId - Base64url credential ID.
   * @returns {Promise<number>} The new sign count.
   */
  async function incrementSignCount(credentialId) {
    _requireUnlocked();
    const entry = _vaultData.passkeys.find(p => p.credentialId === credentialId);
    if (!entry) {
      throw new Error('Passkey not found');
    }
    entry.signCount++;
    entry.lastUsed = Date.now();
    await _persistVault();
    return entry.signCount;
  }

  /**
   * Delete a passkey from the vault.
   * @param {string} credentialId - Base64url credential ID.
   * @returns {Promise<boolean>}
   */
  async function deletePasskey(credentialId) {
    _requireUnlocked();
    const index = _vaultData.passkeys.findIndex(p => p.credentialId === credentialId);
    if (index < 0) return false;
    _vaultData.passkeys.splice(index, 1);
    await _persistVault();
    return true;
  }

  // --- Credential Management ---

  /**
   * Store an encrypted credential (domain/username/password).
   * @param {object} cred - {domain: string, username: string, password: string}
   * @returns {Promise<string>} The generated credential entry ID.
   */
  async function addCredential(cred) {
    _requireUnlocked();
    if (!cred.domain || !cred.username || !cred.password) {
      throw new Error('domain, username, and password are required');
    }

    // Ensure credentials array exists (migration for vaults created before this feature)
    if (!_vaultData.credentials) {
      _vaultData.credentials = [];
    }

    const id = CryptoEngine.base64UrlEncode(CryptoEngine.getRandomBytes(16));
    const encryptedPassword = await CryptoEngine.encryptString(_vaultKey, cred.password);

    _vaultData.credentials.push({
      id,
      domain: cred.domain,
      username: cred.username,
      encryptedPassword,
      createdAt: Date.now()
    });

    await _persistVault();
    return id;
  }

  /**
   * Get all credentials (passwords remain encrypted).
   * @returns {Array<object>}
   */
  function getCredentials() {
    _requireUnlocked();
    return (_vaultData.credentials || []).map(c => ({
      id: c.id,
      domain: c.domain,
      username: c.username,
      createdAt: c.createdAt
    }));
  }

  /**
   * Decrypt and return the password for a credential.
   * @param {string} id - Credential entry ID.
   * @returns {Promise<string>}
   */
  async function getDecryptedPassword(id) {
    _requireUnlocked();
    const entry = (_vaultData.credentials || []).find(c => c.id === id);
    if (!entry) throw new Error('Credential not found');
    return CryptoEngine.decryptString(_vaultKey, entry.encryptedPassword);
  }

  /**
   * Delete a credential from the vault.
   * @param {string} id - Credential entry ID.
   * @returns {Promise<boolean>}
   */
  async function deleteCredential(id) {
    _requireUnlocked();
    if (!_vaultData.credentials) return false;
    const index = _vaultData.credentials.findIndex(c => c.id === id);
    if (index < 0) return false;
    _vaultData.credentials.splice(index, 1);
    await _persistVault();
    return true;
  }

  // --- Policies ---

  /**
   * Get vault policies.
   * @returns {object}
   */
  function getPolicies() {
    _requireUnlocked();
    return { ..._vaultData.policies };
  }

  /**
   * Update vault policies.
   * @param {object} updates - Policy fields to update.
   * @returns {Promise<void>}
   */
  async function updatePolicies(updates) {
    _requireUnlocked();
    Object.assign(_vaultData.policies, updates);
    await _persistVault();
    _resetLockTimer();
  }

  /**
   * Get a summary of vault contents without sensitive data.
   * @returns {object}
   */
  function getSummary() {
    _requireUnlocked();
    return {
      version: _vaultData.version,
      userCount: _vaultData.users.length,
      passkeyCount: _vaultData.passkeys.length,
      credentialCount: (_vaultData.credentials || []).length,
      passkeys: _vaultData.passkeys.map(p => ({
        credentialId: p.credentialId,
        rpId: p.rpId,
        rpName: p.rpName,
        userId: p.userId,
        signCount: p.signCount,
        createdAt: p.createdAt,
        lastUsed: p.lastUsed
      }))
    };
  }

  // --- Tamper Detection ---

  /**
   * Verify vault integrity by attempting decryption.
   * @returns {Promise<boolean>}
   */
  async function verifyIntegrity() {
    if (!_vaultKey) return false;
    try {
      const stored = await chrome.storage.local.get(VAULT_STORAGE_KEY);
      await _decryptVault(_vaultKey, stored[VAULT_STORAGE_KEY]);
      return true;
    } catch {
      return false;
    }
  }

  // --- Internal Helpers ---

  function _requireUnlocked() {
    if (!isUnlocked()) {
      throw new Error('Vault is locked');
    }
  }

  async function _getMeta() {
    const result = await chrome.storage.local.get(VAULT_META_KEY);
    return result[VAULT_META_KEY] || null;
  }

  async function _encryptVault(key, data) {
    const json = JSON.stringify(data);
    return CryptoEngine.encryptString(key, json);
  }

  async function _decryptVault(key, encrypted) {
    const json = await CryptoEngine.decryptString(key, encrypted);
    return JSON.parse(json);
  }

  async function _persistVault() {
    _requireUnlocked();
    const encrypted = await _encryptVault(_vaultKey, _vaultData);
    await chrome.storage.local.set({ [VAULT_STORAGE_KEY]: encrypted });
    _resetLockTimer();
  }

  function _resetLockTimer() {
    if (_lockTimer !== null) {
      clearTimeout(_lockTimer);
    }
    const timeout = _vaultData?.policies?.lockTimeoutMs || DEFAULT_LOCK_TIMEOUT_MS;
    _lockTimer = setTimeout(() => {
      lock();
    }, timeout);
  }

  return Object.freeze({
    exists,
    create,
    unlock,
    lock,
    isUnlocked,
    destroy,

    addUser,
    getUsers,
    findUserByUpn,

    storePasskey,
    getPasskey,
    getPasskeysByRpId,
    getPasskeysByUserId,
    getDecryptedPrivateKey,
    incrementSignCount,
    deletePasskey,

    addCredential,
    getCredentials,
    getDecryptedPassword,
    deleteCredential,

    getPolicies,
    updatePolicies,
    getSummary,
    verifyIntegrity
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.VaultEngine = VaultEngine;
}
