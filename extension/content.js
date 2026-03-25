/**
 * Content Script - PasskeyVault page-level authentication orchestrator.
 * Production version with Microsoft login stage detection.
 */
'use strict';
(() => {
  if (window.__passkeyVaultInjected) return;
  window.__passkeyVaultInjected = true;

  let hasSubmitted = false;
  let isProcessing = false;

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

  init();

  function init() {
    interceptWebAuthnApi();
    observeDomChanges();
    detectLoginStage();
  }

  /* ------------------------------------------------ */
  /* LOGIN STAGE DETECTION                            */
  /* ------------------------------------------------ */
  function detectLoginStage() {
    const usernameField = document.querySelector(MICROSOFT_LOGIN_SELECTORS.usernameInput);
    const passwordField = document.querySelector(MICROSOFT_LOGIN_SELECTORS.passwordInput);
    const otherWay = document.querySelector('#signInAnotherWay');
    const passwordOption = document.querySelector('[data-value="Password"]');

    if (usernameField && !passwordField) {
      attemptUsernameFill();
    }

    if (passwordField) {
      attemptPasswordFill();
    }

    if (otherWay && !hasSubmitted) {
      hasSubmitted = true;
      setTimeout(() => otherWay.click(), 400);
      return;
    }

    if (passwordOption && !hasSubmitted) {
      hasSubmitted = true;
      setTimeout(() => passwordOption.click(), 400);
    }
  }

  /* ------------------------------------------------ */
  /* SIMULATE REAL USER INPUT (React/Angular compat)  */
  /* ------------------------------------------------ */
  function simulateInput(element, value) {
    // React tracks values via its own internal fiber; setting .value alone
    // won't trigger onChange handlers. We need to use the native setter
    // and dispatch the full event sequence browsers fire on real input.
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    ).set;
    nativeInputValueSetter.call(element, value);

    element.dispatchEvent(new Event('input', { bubbles: true }));
    element.dispatchEvent(new Event('change', { bubbles: true }));
  }

  /* ------------------------------------------------ */
  /* USERNAME STAGE                                   */
  /* ------------------------------------------------ */
  async function attemptUsernameFill() {
    if (isProcessing) return;
    try {
      // Use getLoginHint which checks credentials first, then passkey users
      const hint = await sendToBackground('vault.getLoginHint', {
        domain: window.location.hostname
      });
      if (!hint || !hint.username) return;

      const usernameField = document.querySelector(MICROSOFT_LOGIN_SELECTORS.usernameInput);
      if (!usernameField || usernameField.value) return; // Don't overwrite existing input

      isProcessing = true;
      simulateInput(usernameField, hint.username);
      usernameField.focus();

      const next = document.querySelector(MICROSOFT_LOGIN_SELECTORS.nextButton);
      if (next && !hasSubmitted) {
        hasSubmitted = true;
        setTimeout(() => {
          next.click();
          isProcessing = false;
        }, 800);
      } else {
        isProcessing = false;
      }
    } catch {
      isProcessing = false;
      // Vault may be locked; silently fail
    }
  }

  /* ------------------------------------------------ */
  /* PASSWORD STAGE                                   */
  /* ------------------------------------------------ */
  async function attemptPasswordFill() {
    if (isProcessing) return;
    try {
      const credential = await sendToBackground('vault.getCredential', {
        domain: window.location.hostname
      });
      if (!credential) return;

      const passwordField = document.querySelector(MICROSOFT_LOGIN_SELECTORS.passwordInput);
      if (!passwordField) return;

      isProcessing = true;
      simulateInput(passwordField, credential.password);
      passwordField.focus();

      const submit = document.querySelector(MICROSOFT_LOGIN_SELECTORS.nextButton) ||
                     document.querySelector(MICROSOFT_LOGIN_SELECTORS.submitButton);
      if (submit && !hasSubmitted) {
        hasSubmitted = true;
        setTimeout(() => {
          submit.click();
          isProcessing = false;
        }, 800);
      } else {
        isProcessing = false;
      }
    } catch {
      isProcessing = false;
    }
  }

  /* ------------------------------------------------ */
  /* DOM OBSERVER (THROTTLED)                         */
  /* ------------------------------------------------ */
  let observerTimeout;
  function observeDomChanges() {
    const observer = new MutationObserver(() => {
      clearTimeout(observerTimeout);
      observerTimeout = setTimeout(() => {
        detectLoginStage();
        detectPasskeyPrompt();
      }, 300);
    });
    observer.observe(document.documentElement, {
      childList: true,
      subtree: true
    });
  }

  /* ------------------------------------------------ */
  /* PASSKEY PROMPT HANDLING                          */
  /* ------------------------------------------------ */
  function detectPasskeyPrompt() {
    const fidoLink = document.querySelector(MICROSOFT_LOGIN_SELECTORS.fidoLink);
    const passkeyOption = document.querySelector(MICROSOFT_LOGIN_SELECTORS.passkeyOption);
    if (fidoLink || passkeyOption) {
      handlePasskeyPromptDetected();
    }
  }

  function handlePasskeyPromptDetected() {
    if (isProcessing) return;
    sendToBackground('auth.getAvailable', {
      rpId: window.location.hostname
    }).then((response) => {
      if (response.passkeys && response.passkeys.length > 0) {
        const fidoLink = document.querySelector(MICROSOFT_LOGIN_SELECTORS.fidoLink);
        const passkeyOption = document.querySelector(MICROSOFT_LOGIN_SELECTORS.passkeyOption);
        const target = fidoLink || passkeyOption;
        if (target) target.click();
      }
    });
  }

  /* ------------------------------------------------ */
  /* WEBAUTHN INTERCEPTION                            */
  /* ------------------------------------------------ */
  function interceptWebAuthnApi() {
    if (!navigator.credentials) return;

    // --- Intercept navigator.credentials.create() ---
    const originalCreate = navigator.credentials.create.bind(navigator.credentials);

    navigator.credentials.create = async function(options) {
      if (!options || !options.publicKey) {
        return originalCreate(options);
      }

      const publicKeyOptions = options.publicKey;
      const rpId = publicKeyOptions.rp?.id || window.location.hostname;
      const rpName = publicKeyOptions.rp?.name || rpId;

      const originCheck = await sendToBackground('security.validateOrigin', {
        origin: window.location.origin
      });
      if (!originCheck || !originCheck.valid) {
        return originalCreate(options);
      }

      // Check if ES256 (alg -7) is in the allowed algorithms
      const supportsES256 = (publicKeyOptions.pubKeyCredParams || [])
        .some(p => p.alg === -7);
      if (!supportsES256) {
        return originalCreate(options);
      }

      const challengeB64 = arrayBufferToBase64Url(publicKeyOptions.challenge);
      const user = {
        id: arrayBufferToBase64Url(publicKeyOptions.user.id),
        name: publicKeyOptions.user.name,
        displayName: publicKeyOptions.user.displayName
      };

      try {
        const response = await sendToBackground('content.webauthnCreate', {
          rpId,
          rpName,
          user,
          challenge: challengeB64,
          origin: window.location.origin,
          attestation: publicKeyOptions.attestation || 'none'
        });

        if (response && response.registration) {
          return buildCreateResponse(response.registration);
        }

        if (response && response.action === 'requestUnlock') {
          showNotification('PasskeyVault is locked - unlock to register passkeys');
        }

        return originalCreate(options);
      } catch {
        return originalCreate(options);
      }
    };

    // --- Intercept navigator.credentials.get() ---
    const originalGet = navigator.credentials.get.bind(navigator.credentials);

    navigator.credentials.get = async function(options) {
      if (!options || !options.publicKey) {
        return originalGet(options);
      }

      const publicKeyOptions = options.publicKey;
      const rpId = publicKeyOptions.rpId || window.location.hostname;

      const originCheck = await sendToBackground('security.validateOrigin', {
        origin: window.location.origin
      });
      if (!originCheck || !originCheck.valid) {
        return originalGet(options);
      }

      const challengeB64 = arrayBufferToBase64Url(publicKeyOptions.challenge);
      const allowCredentials = (publicKeyOptions.allowCredentials || []).map(c => ({
        id: arrayBufferToBase64Url(c.id),
        type: c.type
      }));

      try {
        const response = await sendToBackground('content.webauthnDetected', {
          rpId,
          challenge: challengeB64,
          origin: window.location.origin,
          allowCredentials
        });

        if (response.action === 'signedAssertion') {
          return buildCredentialResponse(response.assertion);
        }

        if (response.action === 'requestUnlock') {
          showNotification('PasskeyVault locked');
        }

        return originalGet(options);
      } catch {
        return originalGet(options);
      }
    };
  }

  /* ------------------------------------------------ */
  /* BUILD WEBAUTHN RESPONSES                         */
  /* ------------------------------------------------ */

  /**
   * Build a PublicKeyCredential response for navigator.credentials.create().
   */
  function buildCreateResponse(registration) {
    const credentialId = registration.credentialId;
    const rawId = base64UrlToArrayBuffer(registration.credentialIdRaw || credentialId);
    const attestationObject = base64UrlToArrayBuffer(registration.attestationObject);
    const clientDataJSON = base64UrlToArrayBuffer(registration.clientDataJSON);

    const response = {
      id: credentialId,
      rawId: rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        attestationObject: attestationObject,
        clientDataJSON: clientDataJSON,
        getTransports: () => ['internal'],
        getPublicKeyAlgorithm: () => -7,
        getAuthenticatorData: () => {
          // Extract authData from the attestation object (first field after CBOR map header)
          // The RP can also get this from the attestation object directly
          return attestationObject;
        }
      },
      getClientExtensionResults: () => ({})
    };

    // Add getPublicKey if SPKI data available
    if (registration.publicKeySpki) {
      response.response.getPublicKey = () => base64UrlToArrayBuffer(registration.publicKeySpki);
    }

    return response;
  }

  /**
   * Build a PublicKeyCredential response for navigator.credentials.get().
   */
  function buildCredentialResponse(assertion) {
    return {
      id: assertion.credentialId,
      rawId: base64UrlToArrayBuffer(assertion.credentialId),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        authenticatorData: base64UrlToArrayBuffer(assertion.authenticatorData),
        clientDataJSON: base64UrlToArrayBuffer(assertion.clientDataJSON),
        signature: base64UrlToArrayBuffer(assertion.signature),
        userHandle: assertion.userHandle ? base64UrlToArrayBuffer(assertion.userHandle) : null
      },
      getClientExtensionResults: () => ({})
    };
  }

  /* ------------------------------------------------ */
  /* BACKGROUND MESSAGING                             */
  /* ------------------------------------------------ */
  function sendToBackground(action, payload) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ action, payload }, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
          return;
        }
        resolve(response);
      });
    });
  }

  /* ------------------------------------------------ */
  /* UI NOTIFICATION                                  */
  /* ------------------------------------------------ */
  function showNotification(text) {
    const banner = document.createElement('div');
    banner.textContent = text;
    Object.assign(banner.style, {
      position: 'fixed',
      top: '10px',
      right: '10px',
      padding: '10px 16px',
      background: '#0078d4',
      color: '#fff',
      borderRadius: '6px',
      zIndex: '999999'
    });
    document.body.appendChild(banner);
    setTimeout(() => banner.remove(), 4000);
  }

  /* ------------------------------------------------ */
  /* UTILS                                            */
  /* ------------------------------------------------ */
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
    while (base64.length % 4) base64 += '=';
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
})();
