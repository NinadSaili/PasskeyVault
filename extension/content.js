/**
 * Content Script - PasskeyVault page-level authentication orchestrator.
 * Handles Microsoft Entra ID login: auto-fill credentials, intercept WebAuthn.
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
    nextButton: '#idSIButton9',
    submitButton: 'input[type="submit"], button[type="submit"]',
    fidoLink: '#fidoLink, a[data-value="FidoCredential"]',
    passkeyOption: '[data-value="Fido2"], [data-value="FidoCredential"]',
    otherWayToSignIn: '#signInAnotherWay',
    passwordOption: '[data-value="Password"]',
    accountTile: '.table[role="option"], .tile-container .table, [data-test-id="accountTile"]',
    useAnotherAccount: '#otherTile, #otherTileText, [data-test-id="otherTile"]'
  };

  init();

  function init() {
    log('Content script loaded on', window.location.hostname, window.location.pathname);
    interceptWebAuthnApi();
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', startDetection);
    } else {
      startDetection();
    }
  }

  function startDetection() {
    log('Starting login detection');
    observeDomChanges();
    // Poll to catch dynamically rendered forms
    let attempts = 0;
    function poll() {
      attempts++;
      detectLoginStage();
      if (attempts < 10 && !hasFilledUsername) {
        setTimeout(poll, attempts < 3 ? 500 : 1000);
      }
    }
    poll();
  }

  /* ------------------------------------------------ */
  /* SIMULATE REAL USER INPUT (React/Angular compat)  */
  /* ------------------------------------------------ */
  function simulateInput(element, value) {
    element.focus();
    const nativeSetter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, 'value'
    ).set;
    nativeSetter.call(element, value);
    element.dispatchEvent(new Event('input', { bubbles: true }));
    element.dispatchEvent(new Event('change', { bubbles: true }));
  }

  /* ------------------------------------------------ */
  /* LOGIN STAGE DETECTION                            */
  /*                                                  */
  /* Key insight: Microsoft login pages have BOTH     */
  /* username and password inputs in the DOM at all   */
  /* times. The password field is "hidden" but still  */
  /* has non-zero dimensions. We CANNOT rely on       */
  /* visibility checks. Instead, enforce strict order:*/
  /*   1. Always fill username first                  */
  /*   2. Only fill password AFTER username is done   */
  /* ------------------------------------------------ */
  function detectLoginStage() {
    if (isProcessing) return;

    const usernameField = document.querySelector(SELECTORS.usernameInput);
    const passwordField = document.querySelector(SELECTORS.passwordInput);
    const accountTiles = document.querySelectorAll(SELECTORS.accountTile);
    const otherWay = document.querySelector(SELECTORS.otherWayToSignIn);
    const passwordOption = document.querySelector(SELECTORS.passwordOption);

    log('Stage:', {
      hasUsername: !!usernameField,
      hasPassword: !!passwordField,
      tiles: accountTiles.length,
      filledUser: hasFilledUsername,
      filledPass: hasFilledPassword
    });

    // STEP 1: Username must be filled first (strict ordering)
    if (!hasFilledUsername) {
      // If there's a username input field, fill it
      if (usernameField) {
        attemptUsernameFill();
        return;
      }
      // Pure account picker page (no input field, only tiles)
      if (accountTiles.length > 0) {
        attemptAccountPickerSelect(accountTiles);
        return;
      }
      // Form not rendered yet — wait for next poll/observer
      return;
    }

    // STEP 2: After username, handle password (only on page reload/navigation)
    if (!hasFilledPassword && passwordField) {
      attemptPasswordFill();
      return;
    }

    // STEP 3: Handle "Sign in another way" or method picker
    if (otherWay) {
      log('Clicking "Sign in another way"');
      isProcessing = true;
      setTimeout(() => { otherWay.click(); isProcessing = false; }, 400);
      return;
    }
    if (passwordOption) {
      log('Clicking "Password" option');
      isProcessing = true;
      setTimeout(() => { passwordOption.click(); isProcessing = false; }, 400);
    }
  }

  /* ------------------------------------------------ */
  /* ACCOUNT PICKER                                   */
  /* ------------------------------------------------ */
  async function attemptAccountPickerSelect(tiles) {
    if (isProcessing) return;
    isProcessing = true;
    log('Account picker with', tiles.length, 'tiles');

    try {
      const hint = await sendToBackground('vault.getLoginHint', {
        domain: window.location.hostname
      });
      if (!hint || !hint.username) {
        log('No login hint for account picker');
        isProcessing = false;
        return;
      }

      const target = hint.username.toLowerCase();
      for (const tile of tiles) {
        if ((tile.textContent || '').toLowerCase().includes(target)) {
          log('Clicking matching tile for:', hint.username);
          hasFilledUsername = true;
          tile.click();
          isProcessing = false;
          return;
        }
      }

      // No match — click "Use another account"
      const useAnother = document.querySelector(SELECTORS.useAnotherAccount);
      if (useAnother) {
        log('No matching tile, clicking "Use another account"');
        useAnother.click();
      }
      isProcessing = false;
    } catch (err) {
      log('Account picker error:', err.message || err);
      isProcessing = false;
    }
  }

  /* ------------------------------------------------ */
  /* USERNAME FILL                                    */
  /* ------------------------------------------------ */
  async function attemptUsernameFill() {
    if (isProcessing || hasFilledUsername) return;
    isProcessing = true;
    log('Attempting username fill');

    try {
      const hint = await sendToBackground('vault.getLoginHint', {
        domain: window.location.hostname
      });
      log('Login hint:', JSON.stringify(hint));

      const username = hint && hint.username;
      if (!username) {
        log('No username available from vault');
        isProcessing = false;
        return;
      }

      const field = document.querySelector(SELECTORS.usernameInput);
      if (!field) {
        log('Username field gone from DOM');
        isProcessing = false;
        return;
      }

      log('Filling username:', username, '(source:', hint.source + ')');
      simulateInput(field, username);
      hasFilledUsername = true;

      const next = document.querySelector(SELECTORS.nextButton);
      if (next) {
        log('Clicking Next in 800ms');
        setTimeout(() => { next.click(); isProcessing = false; }, 800);
      } else {
        isProcessing = false;
      }
    } catch (err) {
      log('Username fill error:', err.message || err);
      isProcessing = false;
    }
  }

  /* ------------------------------------------------ */
  /* PASSWORD FILL                                    */
  /* ------------------------------------------------ */
  async function attemptPasswordFill() {
    if (isProcessing || hasFilledPassword) return;
    isProcessing = true;
    log('Attempting password fill');

    try {
      const cred = await sendToBackground('vault.getCredential', {
        domain: window.location.hostname
      });
      log('Credential lookup:', cred ? 'found' : 'null');

      if (!cred || !cred.password) {
        log('No credential/password for this domain');
        isProcessing = false;
        return;
      }

      const field = document.querySelector(SELECTORS.passwordInput);
      if (!field) {
        log('Password field not found');
        isProcessing = false;
        return;
      }

      log('Filling password');
      simulateInput(field, cred.password);
      hasFilledPassword = true;

      const submit = document.querySelector(SELECTORS.nextButton) ||
                     document.querySelector(SELECTORS.submitButton);
      if (submit) {
        log('Clicking submit in 800ms');
        setTimeout(() => { submit.click(); isProcessing = false; }, 800);
      } else {
        isProcessing = false;
      }
    } catch (err) {
      log('Password fill error:', err.message || err);
      isProcessing = false;
    }
  }

  /* ------------------------------------------------ */
  /* DOM OBSERVER                                     */
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
      if (response && response.passkeys && response.passkeys.length > 0) {
        const target = document.querySelector(SELECTORS.fidoLink) ||
                       document.querySelector(SELECTORS.passkeyOption);
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

    const originalCreate = navigator.credentials.create.bind(navigator.credentials);
    navigator.credentials.create = async function(options) {
      if (!options || !options.publicKey) return originalCreate(options);

      const pk = options.publicKey;
      const rpId = pk.rp?.id || window.location.hostname;

      const originOk = await sendToBackground('security.validateOrigin', {
        origin: window.location.origin
      });
      if (!originOk || !originOk.valid) return originalCreate(options);
      if (!(pk.pubKeyCredParams || []).some(p => p.alg === -7)) return originalCreate(options);

      try {
        log('Intercepted credentials.create() for rpId:', rpId);
        const response = await sendToBackground('content.webauthnCreate', {
          rpId,
          rpName: pk.rp?.name || rpId,
          user: {
            id: arrayBufferToBase64Url(pk.user.id),
            name: pk.user.name,
            displayName: pk.user.displayName
          },
          challenge: arrayBufferToBase64Url(pk.challenge),
          origin: window.location.origin,
          attestation: pk.attestation || 'none'
        });
        if (response && response.registration) {
          log('Returning vault-generated registration');
          return buildCreateResponse(response.registration);
        }
        if (response && response.action === 'requestUnlock') {
          showNotification('PasskeyVault is locked — unlock to register passkeys');
        }
        return originalCreate(options);
      } catch {
        return originalCreate(options);
      }
    };

    const originalGet = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async function(options) {
      if (!options || !options.publicKey) return originalGet(options);

      const pk = options.publicKey;
      const rpId = pk.rpId || window.location.hostname;

      const originOk = await sendToBackground('security.validateOrigin', {
        origin: window.location.origin
      });
      if (!originOk || !originOk.valid) return originalGet(options);

      try {
        log('Intercepted credentials.get() for rpId:', rpId);
        const response = await sendToBackground('content.webauthnDetected', {
          rpId,
          challenge: arrayBufferToBase64Url(pk.challenge),
          origin: window.location.origin,
          allowCredentials: (pk.allowCredentials || []).map(c => ({
            id: arrayBufferToBase64Url(c.id),
            type: c.type
          }))
        });
        if (response && response.action === 'signedAssertion') {
          log('Returning vault-signed assertion');
          return buildCredentialResponse(response.assertion);
        }
        if (response && response.action === 'requestUnlock') {
          showNotification('PasskeyVault locked — unlock to use passkeys');
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
  function buildCreateResponse(reg) {
    const rawId = base64UrlToArrayBuffer(reg.credentialIdRaw || reg.credentialId);
    const attObj = base64UrlToArrayBuffer(reg.attestationObject);
    const cdj = base64UrlToArrayBuffer(reg.clientDataJSON);
    const resp = {
      id: reg.credentialId,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: {
        attestationObject: attObj,
        clientDataJSON: cdj,
        getTransports: () => ['internal'],
        getPublicKeyAlgorithm: () => -7,
        getAuthenticatorData: () => attObj
      },
      getClientExtensionResults: () => ({})
    };
    if (reg.publicKeySpki) {
      resp.response.getPublicKey = () => base64UrlToArrayBuffer(reg.publicKeySpki);
    }
    return resp;
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
  /* MESSAGING & UI                                   */
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

  function showNotification(text) {
    const banner = document.createElement('div');
    banner.textContent = text;
    Object.assign(banner.style, {
      position: 'fixed', top: '10px', right: '10px',
      padding: '10px 16px', background: '#0078d4', color: '#fff',
      borderRadius: '6px', zIndex: '999999',
      fontFamily: 'Segoe UI, sans-serif', fontSize: '14px'
    });
    document.body.appendChild(banner);
    setTimeout(() => banner.remove(), 4000);
  }

  /* ------------------------------------------------ */
  /* ENCODING UTILS                                   */
  /* ------------------------------------------------ */
  function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function base64UrlToArrayBuffer(b64url) {
    let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  }
})();
