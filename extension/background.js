/**
 * Background Service Worker - PasskeyVault orchestration hub.
 *
 * Responsibilities:
 *   - Load and initialize all engine modules.
 *   - Listen for webNavigation and webRequest events.
 *   - Route messages between content scripts and the popup.
 *   - Coordinate authentication flows (detect → match → sign → respond).
 *   - Manage vault lock/unlock lifecycle via alarms.
 */

'use strict';

// Import engine modules into service worker scope
importScripts(
  'cryptoEngine.js',
  'cborEncoder.js',
  'attestation.js',
  'securityValidator.js',
  'vaultEngine.js',
  'authEngine.js',
  'federationDetector.js'
);

// --- State ---

/** @type {Set<number>} Tabs where we've injected the content script. */
const injectedTabs = new Set();

// --- Initialization ---

chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    // Set default alarm for vault auto-lock check
    chrome.alarms.create('vaultLockCheck', { periodInMinutes: 1 });
  }
});

// Ensure alarm exists on service worker startup
chrome.alarms.create('vaultLockCheck', { periodInMinutes: 1 });

// --- Alarm Handler (Vault Auto-Lock) ---

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'vaultLockCheck') {
    // The VaultEngine handles its own timeout internally,
    // but this ensures the service worker periodically wakes
    // to enforce the lock if the internal timer was lost.
    if (VaultEngine.isUnlocked()) {
      // Touch to keep alive; actual timeout is managed by VaultEngine
    }
  }
});

// --- Web Navigation Monitoring ---

chrome.webNavigation.onBeforeNavigate.addListener(
  (details) => {
    const flow = FederationDetector.handleNavigation(details);
    if (flow) {
      _notifyTab(details.tabId, {
        type: 'AUTH_FLOW_DETECTED',
        flow
      });
    }
  },
  {
    url: [
      { hostSuffix: 'microsoftonline.com' },
      { hostSuffix: 'microsoft.com' },
      { hostSuffix: 'windows.net' },
      { hostSuffix: 'portal.azure.com' }
    ]
  }
);

chrome.webNavigation.onCompleted.addListener(
  (details) => {
    if (details.frameId !== 0) return;

    // Detect auth flow on completed navigation
    const flow = FederationDetector.detectAuthFlow(details.url);
    if (flow) {
      _notifyTab(details.tabId, {
        type: 'AUTH_PAGE_LOADED',
        flow,
        domainType: FederationDetector.detectDomainType(details.url)
      });
    }
  },
  {
    url: [
      { hostSuffix: 'microsoftonline.com' },
      { hostSuffix: 'microsoft.com' },
      { hostSuffix: 'windows.net' }
    ]
  }
);

// --- Web Request Monitoring (SAML/WS-Fed POST detection) ---

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    FederationDetector.handleRequest(details);
  },
  {
    urls: [
      'https://login.microsoftonline.com/*',
      'https://login.microsoft.com/*'
    ],
    types: ['main_frame', 'sub_frame']
  },
  ['requestBody']
);

// --- Message Router ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  _handleMessage(message, sender)
    .then(sendResponse)
    .catch((err) => sendResponse({ error: err.message }));
  return true; // Keep message channel open for async response
});

async function _handleMessage(message, sender) {
  const { action, payload } = message;

  switch (action) {
    // --- Vault Operations ---
    case 'vault.exists':
      return { exists: await VaultEngine.exists() };

    case 'vault.create':
      await VaultEngine.create(payload.pin, payload.options);
      return { success: true };

    case 'vault.unlock':
      return { success: await VaultEngine.unlock(payload.pin) };

    case 'vault.lock':
      VaultEngine.lock();
      return { success: true };

    case 'vault.isUnlocked':
      return { unlocked: VaultEngine.isUnlocked() };

    case 'vault.destroy':
      await VaultEngine.destroy();
      return { success: true };

    case 'vault.summary':
      return VaultEngine.isUnlocked()
        ? { summary: VaultEngine.getSummary() }
        : { error: 'Vault is locked' };

    // --- User Operations ---
    case 'user.add':
      return {
        userId: await VaultEngine.addUser(payload)
      };

    case 'user.list':
      return { users: VaultEngine.getUsers() };

    case 'user.findByUpn':
      return { user: VaultEngine.findUserByUpn(payload.upn) };

    // --- Passkey Operations ---
    case 'passkey.register': {
      const result = await AuthEngine.registerPasskey(payload);
      return { registration: result };
    }

    case 'passkey.list': {
      if (!VaultEngine.isUnlocked()) return { error: 'Vault is locked' };
      const passkeys = payload.rpId
        ? VaultEngine.getPasskeysByRpId(payload.rpId)
        : payload.userId
          ? VaultEngine.getPasskeysByUserId(payload.userId)
          : VaultEngine.getSummary().passkeys;
      return {
        passkeys: passkeys.map(({ encryptedPrivateKey, ...rest }) => rest)
      };
    }

    case 'passkey.delete':
      return { deleted: await VaultEngine.deletePasskey(payload.credentialId) };

    // --- Credential Operations ---
    // --- Domain-based Credential Operations (used by content scripts) ---
    case 'vault.storeCredential':
      await VaultEngine.storeCredential(
        payload.domain,
        payload.username,
        payload.password
      );
      return { success: true };

    case 'vault.getAllCredentials':
      if (!VaultEngine.isUnlocked()) {
        return { credentials: [] };
      }
      return { credentials: VaultEngine.getAllCredentials() };

    case 'vault.getCredential':
      if (!VaultEngine.isUnlocked()) {
        return null;
      }
      return await VaultEngine.getCredential(payload.domain);

    case 'vault.getLoginHint': {
      // Return a username for auto-fill by checking credentials first, then passkey users
      if (!VaultEngine.isUnlocked()) return null;

      // Try credential store first
      const cred = await VaultEngine.getCredential(payload.domain);
      if (cred) return { username: cred.username, source: 'credential' };

      // Fall back to passkey user data — match by RP ID patterns for Microsoft
      const microsoftRpIds = ['login.microsoft.com', 'login.microsoftonline.com'];
      const hostname = (payload.domain || '').toLowerCase();
      const isMicrosoft = microsoftRpIds.some(rp =>
        hostname === rp || hostname.endsWith('.' + rp) ||
        hostname.includes('microsoftonline') || hostname.includes('microsoft.com')
      );

      if (isMicrosoft) {
        for (const rpId of microsoftRpIds) {
          const passkeys = VaultEngine.getPasskeysByRpId(rpId);
          if (passkeys.length > 0) {
            const userId = passkeys[0].userId;
            const users = VaultEngine.getUsers();
            const user = users.find(u => u.userId === userId);
            if (user && user.entraUpn) {
              return { username: user.entraUpn, source: 'passkey' };
            }
          }
        }
      }

      return null;
    }

    // --- ID-based Credential Operations (used by popup) ---
    case 'credential.add':
      return { id: await VaultEngine.addCredential(payload) };

    case 'credential.list':
      return { credentials: VaultEngine.getCredentials() };

    case 'credential.getPassword':
      return { password: await VaultEngine.getDecryptedPassword(payload.id) };

    case 'credential.delete':
      return { deleted: await VaultEngine.deleteCredential(payload.id) };

    // --- Authentication Operations ---
    case 'auth.sign': {
      const assertion = await AuthEngine.signChallenge({
        credentialId: payload.credentialId,
        rpId: payload.rpId,
        challenge: CryptoEngine.base64UrlDecode(payload.challenge),
        origin: payload.origin,
        userVerification: payload.userVerification !== false
      });
      return { assertion };
    }

    case 'auth.getAvailable': {
      const available = AuthEngine.getAvailablePasskeys(
        payload.rpId,
        payload.allowCredentials
      );
      return { passkeys: available };
    }

    // --- Federation Detection ---
    case 'federation.analyze': {
      const analysis = FederationDetector.analyzePageForAuth(payload);
      return { analysis };
    }

    case 'federation.getFlow': {
      const tabId = sender.tab ? sender.tab.id : payload.tabId;
      return { flow: FederationDetector.getActiveFlow(tabId) };
    }

    // --- Security Validation ---
    case 'security.validateOrigin':
      return SecurityValidator.validateOrigin(payload.origin);

    case 'security.validateSigningRequest':
      return SecurityValidator.validateSigningRequest(payload);

    // --- Content Script Signals ---
    case 'content.webauthnCreate': {
      // Content script intercepted navigator.credentials.create()
      if (!VaultEngine.isUnlocked()) {
        return { action: 'requestUnlock' };
      }

      try {
        const registration = await AuthEngine.registerFromWebAuthn({
          rpId: payload.rpId,
          rpName: payload.rpName,
          user: payload.user,
          challenge: payload.challenge,
          origin: payload.origin
        });
        return { registration };
      } catch (err) {
        return { action: 'registrationError', error: err.message };
      }
    }

    case 'content.webauthnDetected': {
      // Content script detected a WebAuthn API call on the page
      const tabId = sender.tab ? sender.tab.id : null;
      if (!tabId) return { error: 'No tab context' };

      if (!VaultEngine.isUnlocked()) {
        return { action: 'requestUnlock' };
      }

      // Find matching passkeys for this RP
      const rpId = payload.rpId;
      const available = AuthEngine.getAvailablePasskeys(rpId, payload.allowCredentials);

      if (available.length === 0) {
        return { action: 'noPasskeys', rpId };
      }

      if (available.length === 1) {
        // Auto-sign with the single available passkey
        try {
          const assertion = await AuthEngine.signChallenge({
            credentialId: available[0].credentialId,
            rpId,
            challenge: CryptoEngine.base64UrlDecode(payload.challenge),
            origin: payload.origin,
            userVerification: true
          });
          return { action: 'signedAssertion', assertion };
        } catch (err) {
          return { action: 'signError', error: err.message };
        }
      }

      // Multiple passkeys: let the user choose
      return { action: 'selectPasskey', passkeys: available };
    }

    default:
      return { error: `Unknown action: ${action}` };
  }
}

// --- Tab Communication ---

async function _notifyTab(tabId, message) {
  try {
    await chrome.tabs.sendMessage(tabId, message);
  } catch {
    // Tab may not have content script loaded yet; that's OK
  }
}

// --- Federation Event Handling ---

FederationDetector.onEvent((eventType, data) => {
  if (data.tabId) {
    _notifyTab(data.tabId, {
      type: 'FEDERATION_EVENT',
      eventType,
      data
    });
  }
});
