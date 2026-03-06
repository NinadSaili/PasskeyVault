/**
 * FederationDetector - Detect and classify Microsoft Entra authentication flows.
 *
 * Monitors browser navigation events and page content to detect:
 *   - OIDC authorization redirects
 *   - SAML POST forms
 *   - WS-Federation requests
 *   - ADFS redirect patterns
 *   - Managed vs. federated domain logins
 *
 * Emits structured events that the background service worker
 * and content scripts use to orchestrate authentication.
 */

const FederationDetector = (() => {
  'use strict';

  // --- Authentication Flow Patterns ---

  const AUTH_FLOW_TYPES = Object.freeze({
    OIDC_AUTHORIZE: 'oidc_authorize',
    OIDC_TOKEN: 'oidc_token',
    SAML_REQUEST: 'saml_request',
    SAML_RESPONSE: 'saml_response',
    WS_FED_SIGNIN: 'ws_fed_signin',
    WS_FED_SIGNOUT: 'ws_fed_signout',
    ADFS_REDIRECT: 'adfs_redirect',
    WEBAUTHN_CHALLENGE: 'webauthn_challenge',
    MANAGED_LOGIN: 'managed_login',
    FEDERATED_LOGIN: 'federated_login',
    UNKNOWN: 'unknown'
  });

  const DOMAIN_TYPE = Object.freeze({
    MANAGED: 'managed',
    FEDERATED: 'federated',
    UNKNOWN: 'unknown'
  });

  /**
   * URL patterns for Microsoft Entra authentication endpoints.
   */
  const ENTRA_AUTH_PATTERNS = [
    {
      pattern: /^https:\/\/login\.microsoftonline\.com\/[^/]+\/oauth2\/v2\.0\/authorize/,
      type: AUTH_FLOW_TYPES.OIDC_AUTHORIZE,
      description: 'Entra ID OIDC Authorization'
    },
    {
      pattern: /^https:\/\/login\.microsoftonline\.com\/[^/]+\/oauth2\/v2\.0\/token/,
      type: AUTH_FLOW_TYPES.OIDC_TOKEN,
      description: 'Entra ID OIDC Token'
    },
    {
      pattern: /^https:\/\/login\.microsoftonline\.com\/[^/]+\/saml2/,
      type: AUTH_FLOW_TYPES.SAML_REQUEST,
      description: 'Entra ID SAML'
    },
    {
      pattern: /^https:\/\/login\.microsoftonline\.com\/[^/]+\/wsfed/,
      type: AUTH_FLOW_TYPES.WS_FED_SIGNIN,
      description: 'Entra ID WS-Federation'
    },
    {
      pattern: /^https:\/\/login\.microsoftonline\.com\/[^/]+\/oauth2\/authorize/,
      type: AUTH_FLOW_TYPES.OIDC_AUTHORIZE,
      description: 'Entra ID OIDC v1 Authorization'
    },
    {
      pattern: /^https:\/\/login\.microsoft\.com\/[^/]+\/oauth2/,
      type: AUTH_FLOW_TYPES.OIDC_AUTHORIZE,
      description: 'Microsoft Login OIDC'
    }
  ];

  /**
   * ADFS / Federation redirect detection patterns.
   */
  const FEDERATION_REDIRECT_PATTERNS = [
    /[?&]whr=/i,                        // Home realm hint
    /[?&]domain_hint=/i,                // Domain hint
    /\/adfs\/ls\//i,                    // ADFS login service
    /\/adfs\/oauth2\//i,                // ADFS OAuth2
    /\/federationmetadata\//i,          // Federation metadata
    /[?&]wa=wsignin1\.0/i,             // WS-Federation sign-in
    /[?&]SAMLRequest=/i,               // SAML request in URL
    /[?&]wctx=/i                        // WS-Federation context
  ];

  /** @type {Array<Function>} Event listeners. */
  const _listeners = [];

  /** @type {Map<number, object>} Active auth flows tracked by tab ID. */
  const _activeFlows = new Map();

  // --- Flow Detection ---

  /**
   * Analyze a URL to detect authentication flow type.
   * @param {string} url - The URL to analyze.
   * @returns {object|null} Detected flow info or null.
   */
  function detectAuthFlow(url) {
    if (!url || typeof url !== 'string') return null;

    for (const { pattern, type, description } of ENTRA_AUTH_PATTERNS) {
      if (pattern.test(url)) {
        const flowInfo = {
          type,
          description,
          url: SecurityValidator.sanitizeUrlForLogging(url),
          timestamp: Date.now(),
          metadata: _extractUrlMetadata(url)
        };
        return flowInfo;
      }
    }

    // Check for federation redirects
    if (_isFederationRedirect(url)) {
      return {
        type: AUTH_FLOW_TYPES.ADFS_REDIRECT,
        description: 'Federation redirect detected',
        url: SecurityValidator.sanitizeUrlForLogging(url),
        timestamp: Date.now(),
        metadata: _extractUrlMetadata(url)
      };
    }

    return null;
  }

  /**
   * Detect whether a domain is managed (cloud-only) or federated
   * based on URL patterns and metadata.
   *
   * @param {string} url - Current URL.
   * @param {object} [pageData] - Optional page content signals.
   * @returns {{type: string, federationEndpoint?: string}}
   */
  function detectDomainType(url, pageData = {}) {
    try {
      const parsed = new URL(url);
      const params = parsed.searchParams;

      // Federated signals: WHR parameter, domain_hint, ADFS paths
      if (params.has('whr') || params.has('domain_hint')) {
        const hint = params.get('whr') || params.get('domain_hint');
        return {
          type: DOMAIN_TYPE.FEDERATED,
          hint,
          federationEndpoint: _extractFederationEndpoint(url, pageData)
        };
      }

      // ADFS path patterns indicate federation
      if (/\/adfs\//i.test(parsed.pathname)) {
        return {
          type: DOMAIN_TYPE.FEDERATED,
          federationEndpoint: parsed.origin + parsed.pathname
        };
      }

      // If on login.microsoftonline.com without federation hints, likely managed
      if (parsed.hostname === 'login.microsoftonline.com') {
        return { type: DOMAIN_TYPE.MANAGED };
      }

      return { type: DOMAIN_TYPE.UNKNOWN };
    } catch {
      return { type: DOMAIN_TYPE.UNKNOWN };
    }
  }

  /**
   * Analyze page content for WebAuthn challenge indicators.
   * Called by content script after page load.
   *
   * @param {object} pageSignals - Signals from the content script.
   * @param {boolean} pageSignals.hasWebAuthnApi - navigator.credentials available.
   * @param {boolean} pageSignals.hasPasskeyPrompt - UI indicating passkey prompt.
   * @param {string} pageSignals.pageUrl - Current page URL.
   * @returns {object} Analysis result.
   */
  function analyzePageForAuth(pageSignals) {
    const result = {
      isAuthPage: false,
      flowType: AUTH_FLOW_TYPES.UNKNOWN,
      shouldIntercept: false,
      domainType: DOMAIN_TYPE.UNKNOWN
    };

    if (!pageSignals || !pageSignals.pageUrl) return result;

    // Detect the flow from URL
    const flow = detectAuthFlow(pageSignals.pageUrl);
    if (flow) {
      result.isAuthPage = true;
      result.flowType = flow.type;
    }

    // Check domain type
    const domain = detectDomainType(pageSignals.pageUrl);
    result.domainType = domain.type;

    // Determine if we should intercept
    if (result.isAuthPage && pageSignals.hasWebAuthnApi) {
      result.shouldIntercept = true;
    }

    // If we see passkey prompt UI elements, definitely intercept
    if (pageSignals.hasPasskeyPrompt) {
      result.shouldIntercept = true;
      result.flowType = AUTH_FLOW_TYPES.WEBAUTHN_CHALLENGE;
    }

    return result;
  }

  // --- Navigation Monitoring ---

  /**
   * Handle a web navigation event (called from background service worker).
   * Tracks authentication flows across tab navigations.
   *
   * @param {object} details - Chrome webNavigation event details.
   * @returns {object|null} Flow detection result.
   */
  function handleNavigation(details) {
    const { tabId, url, frameId } = details;

    // Only track main frame navigations
    if (frameId !== 0) return null;

    const flow = detectAuthFlow(url);
    if (!flow) {
      // If navigating away from auth, clear tracking
      if (_activeFlows.has(tabId)) {
        const existing = _activeFlows.get(tabId);
        if (!SecurityValidator.isMicrosoftAuthDomain(url)) {
          _activeFlows.delete(tabId);
          _emit('flowComplete', { tabId, flow: existing });
        }
      }
      return null;
    }

    // Track or update flow
    const existingFlow = _activeFlows.get(tabId);
    const flowRecord = {
      ...flow,
      tabId,
      steps: existingFlow ? [...existingFlow.steps, flow] : [flow],
      domainType: detectDomainType(url)
    };

    _activeFlows.set(tabId, flowRecord);
    _emit('flowDetected', flowRecord);

    return flowRecord;
  }

  /**
   * Handle a web request to detect SAML POST or WS-Fed forms.
   * @param {object} details - Chrome webRequest event details.
   * @returns {object|null}
   */
  function handleRequest(details) {
    const { tabId, url, method, requestBody } = details;

    if (method !== 'POST') return null;

    // Detect SAML response POST
    if (requestBody && requestBody.formData) {
      const formData = requestBody.formData;

      if (formData.SAMLResponse) {
        const flow = {
          type: AUTH_FLOW_TYPES.SAML_RESPONSE,
          description: 'SAML Response POST detected',
          url: SecurityValidator.sanitizeUrlForLogging(url),
          timestamp: Date.now(),
          tabId
        };
        _emit('samlResponseDetected', flow);
        return flow;
      }

      if (formData.wresult || formData.wa) {
        const flow = {
          type: AUTH_FLOW_TYPES.WS_FED_SIGNIN,
          description: 'WS-Federation sign-in POST detected',
          url: SecurityValidator.sanitizeUrlForLogging(url),
          timestamp: Date.now(),
          tabId
        };
        _emit('wsFedDetected', flow);
        return flow;
      }
    }

    return null;
  }

  /**
   * Get the current authentication flow for a tab.
   * @param {number} tabId - Browser tab ID.
   * @returns {object|null}
   */
  function getActiveFlow(tabId) {
    return _activeFlows.get(tabId) || null;
  }

  /**
   * Clear flow tracking for a tab.
   * @param {number} tabId
   */
  function clearFlow(tabId) {
    _activeFlows.delete(tabId);
  }

  // --- Event System ---

  /**
   * Register a listener for federation detection events.
   * @param {Function} callback - Event handler: (eventType, data) => void
   * @returns {Function} Unsubscribe function.
   */
  function onEvent(callback) {
    _listeners.push(callback);
    return () => {
      const index = _listeners.indexOf(callback);
      if (index >= 0) _listeners.splice(index, 1);
    };
  }

  function _emit(eventType, data) {
    for (const listener of _listeners) {
      try {
        listener(eventType, data);
      } catch {
        // Don't let listener errors break the detection engine
      }
    }
  }

  // --- Internal Helpers ---

  function _isFederationRedirect(url) {
    return FEDERATION_REDIRECT_PATTERNS.some(pattern => pattern.test(url));
  }

  function _extractUrlMetadata(url) {
    try {
      const parsed = new URL(url);
      const params = parsed.searchParams;
      return {
        tenant: _extractTenantId(parsed.pathname),
        clientId: params.get('client_id') || null,
        responseType: params.get('response_type') || null,
        scope: params.get('scope') || null,
        redirectUri: params.get('redirect_uri')
          ? SecurityValidator.sanitizeUrlForLogging(params.get('redirect_uri'))
          : null,
        domainHint: params.get('domain_hint') || params.get('whr') || null,
        loginHint: params.has('login_hint') ? '[PRESENT]' : null,
        nonce: params.has('nonce') ? '[PRESENT]' : null
      };
    } catch {
      return {};
    }
  }

  function _extractTenantId(pathname) {
    const match = pathname.match(/^\/([a-f0-9-]{36}|[^/]+)\//);
    return match ? match[1] : null;
  }

  function _extractFederationEndpoint(url, pageData) {
    // Try to find federation metadata URL from page data or URL params
    if (pageData && pageData.federationMetadataUrl) {
      return pageData.federationMetadataUrl;
    }
    try {
      const parsed = new URL(url);
      // Common ADFS metadata path
      if (parsed.searchParams.has('whr')) {
        return `https://${parsed.searchParams.get('whr')}/adfs/ls/`;
      }
    } catch {
      // ignore
    }
    return null;
  }

  return Object.freeze({
    AUTH_FLOW_TYPES,
    DOMAIN_TYPE,

    detectAuthFlow,
    detectDomainType,
    analyzePageForAuth,
    handleNavigation,
    handleRequest,
    getActiveFlow,
    clearFlow,
    onEvent
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.FederationDetector = FederationDetector;
}
