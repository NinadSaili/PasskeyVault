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
  /* USERNAME STAGE                                   */
  /* ------------------------------------------------ */
  async function attemptUsernameFill() {
    try {
      const credential = await sendToBackground('vault.getCredential', {
        domain: window.location.hostname
      });
      if (!credential) return;

      const usernameField = document.querySelector(MICROSOFT_LOGIN_SELECTORS.usernameInput);
      if (!usernameField) return;

      usernameField.value = credential.username;

      const next = document.querySelector(MICROSOFT_LOGIN_SELECTORS.nextButton);
      if (next && !hasSubmitted) {
        hasSubmitted = true;
        setTimeout(() => next.click(), 600);
      }
    } catch {
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
      passwordField.value = credential.password;

      const submit = document.querySelector(MICROSOFT_LOGIN_SELECTORS.nextButton) ||
                     document.querySelector(MICROSOFT_LOGIN_SELECTORS.submitButton);
      if (submit && !hasSubmitted) {
        hasSubmitted = true;
        setTimeout(() => submit.click(), 700);
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
  /* BUILD WEBAUTHN RESPONSE                          */
  /* ------------------------------------------------ */
  function buildCredentialResponse(assertion) {
    return {
      id: assertion.credentialId,
      rawId: base64UrlToArrayBuffer(assertion.credentialId),
      type: 'public-key',
      response: {
        authenticatorData: base64UrlToArrayBuffer(assertion.authenticatorData),
        clientDataJSON: base64UrlToArrayBuffer(assertion.clientDataJSON),
        signature: base64UrlToArrayBuffer(assertion.signature),
        userHandle: null
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
