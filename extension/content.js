/**
 * Content Script - PasskeyVault page-level authentication orchestrator.
 *
 * Injected into Microsoft login pages. Responsibilities:
 *   - Detect WebAuthn credential requests on the page.
 *   - Intercept navigator.credentials.get() calls.
 *   - Communicate with background service worker for signing.
 *   - Inject signed assertions back into the page flow.
 *   - Detect passkey/FIDO2 UI prompts on Microsoft login pages.
 */

'use strict';

(() => {
  // Prevent double-injection
  if (window.__passkeyVaultInjected) return;
  window.__passkeyVaultInjected = true;

  // --- Configuration ---

  const MICROSOFT_LOGIN_SELECTORS = {
    usernameInput: 'input[name="loginfmt"]',
    passwordInput: 'input[name="passwd"]',
    submitButton: 'input[type="submit"], button[type="submit"]',
    nextButton: '#idSIButton9',
    fidoLink: '#fidoLink, a[data-value="FidoCredential"]',
    passkeyOption: '[data-value="Fido2"], [data-value="FidoCredential"]',
    otherWayToSignIn: '#signInAnotherWay',
    errorMessage: '#passwordError, #usernameError, .alert-error'
  };

  // --- State ---

  let currentPageAnalysis = null;
  let isProcessing = false;

  // --- Initialization ---

  init();

  function init() {
    analyzeCurrentPage();
    observeDomChanges();
    interceptWebAuthnApi();
    listenForBackgroundMessages();
  }

  // --- Page Analysis ---

  function analyzeCurrentPage() {
    const signals = {
      pageUrl: window.location.href,
      hasWebAuthnApi: !!(navigator.credentials && navigator.credentials.get),
      hasPasskeyPrompt: !!document.querySelector(MICROSOFT_LOGIN_SELECTORS.fidoLink)
        || !!document.querySelector(MICROSOFT_LOGIN_SELECTORS.passkeyOption),
      hasUsernameField: !!document.querySelector(MICROSOFT_LOGIN_SELECTORS.usernameInput),
      hasPasswordField: !!document.querySelector(MICROSOFT_LOGIN_SELECTORS.passwordInput)
    };

    sendToBackground('federation.analyze', signals).then((response) => {
      if (response && response.analysis) {
        currentPageAnalysis = response.analysis;

        if (currentPageAnalysis.shouldIntercept) {
          handleAuthInterception();
        }
      }
    });
  }

  // --- DOM Mutation Observer ---

  function observeDomChanges() {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
          // Re-check for passkey prompts when DOM changes
          const fidoLink = document.querySelector(MICROSOFT_LOGIN_SELECTORS.fidoLink);
          const passkeyOption = document.querySelector(MICROSOFT_LOGIN_SELECTORS.passkeyOption);

          if (fidoLink || passkeyOption) {
            if (!isProcessing) {
              handlePasskeyPromptDetected();
            }
          }
        }
      }
    });

    observer.observe(document.body || document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  // --- WebAuthn API Interception ---

  function interceptWebAuthnApi() {
    if (!navigator.credentials) return;

    const originalGet = navigator.credentials.get.bind(navigator.credentials);

    navigator.credentials.get = async function (options) {
      // Only intercept WebAuthn / publicKey requests
      if (!options || !options.publicKey) {
        return originalGet(options);
      }

      const publicKeyOptions = options.publicKey;
      const rpId = publicKeyOptions.rpId || window.location.hostname;

      // Check if this is a Microsoft auth domain we should handle
      const originCheck = await sendToBackground('security.validateOrigin', {
        origin: window.location.origin
      });

      if (!originCheck || !originCheck.valid) {
        // Not a trusted domain, fall through to platform authenticator
        return originalGet(options);
      }

      // Extract challenge
      const challenge = publicKeyOptions.challenge;
      const challengeB64 = arrayBufferToBase64Url(challenge);

      // Extract allowed credentials
      const allowCredentials = (publicKeyOptions.allowCredentials || []).map(cred => ({
        id: arrayBufferToBase64Url(cred.id),
        type: cred.type
      }));

      // Ask background for a signed assertion
      try {
        const response = await sendToBackground('content.webauthnDetected', {
          rpId,
          challenge: challengeB64,
          origin: window.location.origin,
          allowCredentials,
          userVerification: publicKeyOptions.userVerification
        });

        if (response.action === 'signedAssertion' && response.assertion) {
          // Convert the assertion back to the format expected by the page
          return buildCredentialResponse(response.assertion);
        }

        if (response.action === 'requestUnlock') {
          // Vault is locked; show notification and fall through
          showNotification('PasskeyVault is locked. Click the extension icon to unlock.');
          return originalGet(options);
        }

        if (response.action === 'noPasskeys') {
          // No matching passkeys; fall through to platform
          return originalGet(options);
        }

        if (response.action === 'selectPasskey') {
          // Multiple passkeys available - for now auto-select first
          // Future: show selection UI
          const selected = response.passkeys[0];
          const signResponse = await sendToBackground('auth.sign', {
            credentialId: selected.credentialId,
            rpId,
            challenge: challengeB64,
            origin: window.location.origin
          });
          if (signResponse.assertion) {
            return buildCredentialResponse(signResponse.assertion);
          }
        }

        // Fallback to platform authenticator
        return originalGet(options);
      } catch {
        // On any error, fall back to the platform authenticator
        return originalGet(options);
      }
    };
  }

  // --- Passkey Prompt Auto-Click ---

  function handlePasskeyPromptDetected() {
    if (isProcessing) return;
    isProcessing = true;

    // Check if vault is unlocked and has passkeys for this RP
    sendToBackground('auth.getAvailable', {
      rpId: window.location.hostname
    }).then((response) => {
      if (response.passkeys && response.passkeys.length > 0) {
        // Auto-click the FIDO/passkey option to trigger the WebAuthn flow
        const fidoLink = document.querySelector(MICROSOFT_LOGIN_SELECTORS.fidoLink);
        const passkeyOption = document.querySelector(MICROSOFT_LOGIN_SELECTORS.passkeyOption);
        const target = fidoLink || passkeyOption;

        if (target) {
          target.click();
        }
      }
      isProcessing = false;
    }).catch(() => {
      isProcessing = false;
    });
  }

  function handleAuthInterception() {
    // When we detect this is an auth page, check if we can auto-trigger passkey flow
    sendToBackground('vault.isUnlocked', {}).then((response) => {
      if (response.unlocked) {
        // Look for sign-in-another-way link to navigate to passkey option
        const otherWay = document.querySelector(MICROSOFT_LOGIN_SELECTORS.otherWayToSignIn);
        if (otherWay) {
          otherWay.click();
          // The DOM observer will catch the passkey option appearing
        }
      }
    });
  }

  // --- Build WebAuthn Credential Response ---

  function buildCredentialResponse(assertion) {
    // Construct a PublicKeyCredential-like object
    const response = {
      id: assertion.credentialId,
      rawId: base64UrlToArrayBuffer(assertion.credentialId),
      type: assertion.type,
      response: {
        authenticatorData: base64UrlToArrayBuffer(assertion.authenticatorData),
        clientDataJSON: base64UrlToArrayBuffer(assertion.clientDataJSON),
        signature: base64UrlToArrayBuffer(assertion.signature),
        userHandle: assertion.userHandle
          ? base64UrlToArrayBuffer(assertion.userHandle)
          : null
      },
      authenticatorAttachment: 'cross-platform',
      getClientExtensionResults: () => ({})
    };

    return response;
  }

  // --- Background Communication ---

  function sendToBackground(action, payload) {
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

  function listenForBackgroundMessages() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'AUTH_FLOW_DETECTED') {
        currentPageAnalysis = message.flow;
      }
      if (message.type === 'AUTH_PAGE_LOADED') {
        analyzeCurrentPage();
      }
      if (message.type === 'FEDERATION_EVENT') {
        // Track federation events for debugging
      }
      sendResponse({ received: true });
    });
  }

  // --- UI Notifications ---

  function showNotification(text) {
    const banner = document.createElement('div');
    banner.textContent = text;
    Object.assign(banner.style, {
      position: 'fixed',
      top: '10px',
      right: '10px',
      padding: '12px 20px',
      backgroundColor: '#0078d4',
      color: '#ffffff',
      borderRadius: '6px',
      zIndex: '999999',
      fontSize: '14px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
      cursor: 'pointer',
      transition: 'opacity 0.3s'
    });
    banner.addEventListener('click', () => banner.remove());
    document.body.appendChild(banner);

    setTimeout(() => {
      banner.style.opacity = '0';
      setTimeout(() => banner.remove(), 300);
    }, 5000);
  }

  // --- Encoding Utilities ---

  function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64UrlToArrayBuffer(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) base64 += '=';
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
})();
