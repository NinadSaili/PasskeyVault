/**
 * Content Script - PasskeyVault page-level authentication orchestrator.
 * Production version with Microsoft login stage detection.
 */
'use strict';
(() => {
  if (window.__passkeyVaultInjected) return;
  window.__passkeyVaultInjected = true;

  const DEBUG = true;
  function log(...args) {
    if (DEBUG) console.log('[PasskeyVault]', ...args);
  }

  let hasFilledUsername = false;
  let hasFilledPassword = false;
  let isProcessing = false;

  const SELECTORS = {
    usernameInput: 'input[name="loginfmt"]',
    passwordInput: 'input[name="passwd"]',
    submitButton: 'input[type="submit"], button[type="submit"]',
    nextButton: '#idSIButton9',
    fidoLink: '#fidoLink, a[data-value="FidoCredential"]',
    passkeyOption: '[data-value="Fido2"], [data-value="FidoCredential"]',
    otherWayToSignIn: '#signInAnotherWay',
    errorMessage: '#passwordError, #usernameError, .alert-error',
    // Account picker page selectors
    accountTile: '.table[role="option"], .tile-container .table, [data-test-id="accountTile"]',
    useAnotherAccount: '#otherTile, #otherTileText, [data-test-id="otherTile"]'
  };

  init();

  function init() {
    log('Content script loaded on', window.location.hostname, window.location.pathname);
    interceptWebAuthnApi();
    observeDomChanges();
    // Give page time to render dynamic content, then detect
    setTimeout(() => detectLoginStage(), 500);
    setTimeout(() => detectLoginStage(), 1500);
    setTimeout(() => detectLoginStage(), 3000);
  }

  /* ------------------------------------------------ */
  /* SIMULATE REAL USER INPUT (React/Angular compat)  */
  /* ------------------------------------------------ */
  function simulateInput(element, value) {
    element.focus();
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    ).set;
    nativeInputValueSetter.call(element, value);

    element.dispatchEvent(new Event('focus', { bubbles: true }));
    element.dispatchEvent(new Event('input', { bubbles: true }));
    element.dispatchEvent(new Event('change', { bubbles: true }));
    element.dispatchEvent(new Event('blur', { bubbles: true }));
  }

  /* ------------------------------------------------ */
  /* LOGIN STAGE DETECTION                            */
  /* ------------------------------------------------ */
  function detectLoginStage() {
    const usernameField = document.querySelector(SELECTORS.usernameInput);
    const passwordField = document.querySelector(SELECTORS.passwordInput);
    const accountTiles = document.querySelectorAll(SELECTORS.accountTile);
    const otherWay = document.querySelector(SELECTORS.otherWayToSignIn);
    const passwordOption = document.querySelector('[data-value="Password"]');

    log('Stage detection:', {
      hasUsernameField: !!usernameField,
      hasPasswordField: !!passwordField,
      accountTileCount: accountTiles.length,
      hasOtherWay: !!otherWay,
      hasPasswordOption: !!passwordOption,
      hasFilledUsername,
      hasFilledPassword,
      isProcessing
    });

    // Username input page ("Sign in") — prioritize this over account tiles
    // because some pages show both tiles AND the input field
    if (usernameField && !passwordField && !hasFilledUsername) {
      attemptUsernameFill();
      return;
    }

    // Account picker page ("Pick an account" — tiles only, no input field)
    if (accountTiles.length > 0 && !hasFilledUsername && !usernameField) {
      attemptAccountPickerSelect(accountTiles);
      return;
    }

    // Password input page
    if (passwordField && !hasFilledPassword) {
      attemptPasswordFill();
      return;
    }

    // "Sign in another way" prompt
    if (otherWay && !hasFilledPassword) {
      log('Clicking "Sign in another way"');
      setTimeout(() => otherWay.click(), 400);
      return;
    }

    // Password option in the method picker
    if (passwordOption && !hasFilledPassword) {
      log('Clicking "Password" option');
      setTimeout(() => passwordOption.click(), 400);
    }
  }

  /* ------------------------------------------------ */
  /* ACCOUNT PICKER ("Pick an account" page)          */
  /* ------------------------------------------------ */
  async function attemptAccountPickerSelect(tiles) {
    if (isProcessing) return;
    isProcessing = true;
    log('Account picker detected with', tiles.length, 'tiles');

    try {
      const hint = await sendToBackground('vault.getLoginHint', {
        domain: window.location.hostname
      });
      if (!hint || !hint.username) {
        log('No login hint available');
        isProcessing = false;
        return;
      }

      log('Looking for account tile matching:', hint.username);
      const targetEmail = hint.username.toLowerCase();

      // Search all tiles for matching email text
      for (const tile of tiles) {
        const tileText = (tile.textContent || '').toLowerCase();
        if (tileText.includes(targetEmail)) {
          log('Found matching account tile, clicking');
          hasFilledUsername = true;
          tile.click();
          isProcessing = false;
          return;
        }
      }

      // No matching tile found — click "Use another account" if available
      const useAnother = document.querySelector(SELECTORS.useAnotherAccount);
      if (useAnother) {
        log('No matching tile, clicking "Use another account"');
        useAnother.click();
        // After clicking, the username input page should appear
        // The MutationObserver will re-trigger detectLoginStage
      }

      isProcessing = false;
    } catch (err) {
      log('Account picker error:', err);
      isProcessing = false;
    }
  }

  /* ------------------------------------------------ */
  /* USERNAME STAGE                                   */
  /* ------------------------------------------------ */
  async function attemptUsernameFill() {
    if (isProcessing || hasFilledUsername) return;
    isProcessing = true;
    log('Attempting username fill');

    try {
      const hint = await sendToBackground('vault.getLoginHint', {
        domain: window.location.hostname
      });
      log('Login hint response:', hint);

      if (!hint || !hint.username) {
        log('No login hint available');
        isProcessing = false;
        return;
      }

      const usernameField = document.querySelector(SELECTORS.usernameInput);
      if (!usernameField) {
        log('Username field not found');
        isProcessing = false;
        return;
      }

      log('Filling username:', hint.username, '(source:', hint.source + ')');
      simulateInput(usernameField, hint.username);
      hasFilledUsername = true;

      const next = document.querySelector(SELECTORS.nextButton);
      if (next) {
        log('Clicking Next button in 800ms');
        setTimeout(() => {
          next.click();
          isProcessing = false;
        }, 800);
      } else {
        isProcessing = false;
      }
    } catch (err) {
      log('Username fill error:', err);
      isProcessing = false;
    }
  }

  /* ------------------------------------------------ */
  /* PASSWORD STAGE                                   */
  /* ------------------------------------------------ */
  async function attemptPasswordFill() {
    if (isProcessing || hasFilledPassword) return;
    isProcessing = true;
    log('Attempting password fill');

    try {
      const credential = await sendToBackground('vault.getCredential', {
        domain: window.location.hostname
      });
      if (!credential || !credential.password) {
        log('No credential found for password fill');
        isProcessing = false;
        return;
      }

      const passwordField = document.querySelector(SELECTORS.passwordInput);
      if (!passwordField) {
        log('Password field not found');
        isProcessing = false;
        return;
      }

      log('Filling password');
      simulateInput(passwordField, credential.password);
      hasFilledPassword = true;

      const submit = document.querySelector(SELECTORS.nextButton) ||
                     document.querySelector(SELECTORS.submitButton);
      if (submit) {
        log('Clicking submit in 800ms');
        setTimeout(() => {
          submit.click();
          isProcessing = false;
        }, 800);
      } else {
        isProcessing = false;
      }
    } catch (err) {
      log('Password fill error:', err);
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
    const fidoLink = document.querySelector(SELECTORS.fidoLink);
    const passkeyOption = document.querySelector(SELECTORS.passkeyOption);
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
        const fidoLink = document.querySelector(SELECTORS.fidoLink);
        const passkeyOption = document.querySelector(SELECTORS.passkeyOption);
        const target = fidoLink || passkeyOption;
        if (target) {
          log('Clicking passkey option');
          target.click();
        }
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
        getAuthenticatorData: () => attestationObject
      },
      getClientExtensionResults: () => ({})
    };

    if (registration.publicKeySpki) {
      response.response.getPublicKey = () => base64UrlToArrayBuffer(registration.publicKeySpki);
    }

    return response;
  }

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
      zIndex: '999999',
      fontFamily: 'Segoe UI, sans-serif',
      fontSize: '14px'
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
