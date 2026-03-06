/**
 * SecurityValidator - Domain security controls and phishing prevention.
 *
 * Validates origins, RP IDs, and TLS state before any credential
 * release or signing operation. Prevents credential theft via:
 *   - Origin spoofing
 *   - RP ID mismatch
 *   - Non-TLS connections
 *   - Untrusted domains
 */

const SecurityValidator = (() => {
  'use strict';

  /**
   * Trusted Microsoft authentication domains.
   * Only these origins are allowed to trigger credential operations.
   */
  const TRUSTED_MICROSOFT_DOMAINS = Object.freeze([
    'login.microsoftonline.com',
    'login.microsoft.com',
    'login.windows.net',
    'sts.windows.net',
    'portal.azure.com',
    'aadcdn.msftauth.net',
    'msftauth.net',
    'microsoftonline.com'
  ]);

  /**
   * Valid WebAuthn RP IDs for Microsoft Entra authentication.
   */
  const VALID_RP_IDS = Object.freeze([
    'login.microsoft.com',
    'login.microsoftonline.com'
  ]);

  /**
   * Known ADFS domain patterns (federations).
   * These are permitted as redirect targets but not as RP IDs.
   */
  const ADFS_PATTERNS = Object.freeze([
    /^adfs\..+/i,
    /^sts\..+/i,
    /^fs\..+/i,
    /^sso\..+/i
  ]);

  /**
   * Validate that an origin is trusted for credential operations.
   * @param {string} origin - Full origin URL (e.g. "https://login.microsoftonline.com").
   * @returns {{valid: boolean, reason?: string, domain?: string}}
   */
  function validateOrigin(origin) {
    if (!origin || typeof origin !== 'string') {
      return { valid: false, reason: 'Origin is required' };
    }

    let url;
    try {
      url = new URL(origin);
    } catch {
      return { valid: false, reason: 'Invalid origin URL' };
    }

    // Require HTTPS
    if (url.protocol !== 'https:') {
      return { valid: false, reason: 'Only HTTPS origins are trusted' };
    }

    const hostname = url.hostname.toLowerCase();

    // Check against trusted domains
    const isTrusted = TRUSTED_MICROSOFT_DOMAINS.some(domain => {
      return hostname === domain || hostname.endsWith(`.${domain}`);
    });

    if (!isTrusted) {
      // Check if it's an ADFS federation endpoint
      const isAdfs = ADFS_PATTERNS.some(pattern => pattern.test(hostname));
      if (isAdfs) {
        return {
          valid: true,
          domain: hostname,
          federated: true,
          reason: 'ADFS federation endpoint detected'
        };
      }
      return { valid: false, reason: `Untrusted domain: ${hostname}` };
    }

    return { valid: true, domain: hostname };
  }

  /**
   * Validate that an RP ID is legitimate for the given origin.
   * Per WebAuthn spec, the RP ID must be a registrable domain suffix
   * of the origin's effective domain.
   *
   * @param {string} rpId - Relying party identifier.
   * @param {string} origin - Request origin.
   * @returns {{valid: boolean, reason?: string}}
   */
  function validateRpId(rpId, origin) {
    if (!rpId || typeof rpId !== 'string') {
      return { valid: false, reason: 'RP ID is required' };
    }

    if (!origin || typeof origin !== 'string') {
      return { valid: false, reason: 'Origin is required for RP ID validation' };
    }

    const rpIdLower = rpId.toLowerCase();

    // RP ID must be in our valid list or be a suffix of the origin domain
    let url;
    try {
      url = new URL(origin);
    } catch {
      return { valid: false, reason: 'Invalid origin URL' };
    }

    const originDomain = url.hostname.toLowerCase();

    // WebAuthn RP ID validation: rpId must be equal to or a registrable
    // domain suffix of the origin's effective domain
    if (originDomain !== rpIdLower && !originDomain.endsWith(`.${rpIdLower}`)) {
      return {
        valid: false,
        reason: `RP ID "${rpId}" is not a valid suffix of origin "${originDomain}"`
      };
    }

    // Additional check: RP ID should be in our known-good list for
    // Microsoft authentication
    const isKnownRpId = VALID_RP_IDS.includes(rpIdLower);
    if (!isKnownRpId) {
      // Allow custom RP IDs if they pass the suffix check, but flag it
      return {
        valid: true,
        reason: 'RP ID passed suffix validation but is not a known Microsoft RP ID',
        knownRpId: false
      };
    }

    return { valid: true, knownRpId: true };
  }

  /**
   * Validate a WebAuthn challenge before signing.
   * Performs comprehensive pre-signing security checks.
   *
   * @param {object} params
   * @param {string} params.rpId - Relying party ID.
   * @param {string} params.origin - Request origin.
   * @param {ArrayBuffer|Uint8Array} params.challenge - Challenge bytes.
   * @returns {{valid: boolean, reason?: string}}
   */
  function validateSigningRequest(params) {
    const { rpId, origin, challenge } = params;

    // Validate origin
    const originResult = validateOrigin(origin);
    if (!originResult.valid) {
      return originResult;
    }

    // Validate RP ID against origin
    const rpResult = validateRpId(rpId, origin);
    if (!rpResult.valid) {
      return rpResult;
    }

    // Validate challenge is present and reasonable size
    if (!challenge) {
      return { valid: false, reason: 'Challenge is required' };
    }
    const challengeLength = challenge.byteLength || challenge.length;
    if (challengeLength < 16) {
      return { valid: false, reason: 'Challenge too short (minimum 16 bytes)' };
    }
    if (challengeLength > 1024) {
      return { valid: false, reason: 'Challenge too long (maximum 1024 bytes)' };
    }

    return { valid: true };
  }

  /**
   * Check if a URL belongs to a known Microsoft authentication domain.
   * @param {string} url - URL to check.
   * @returns {boolean}
   */
  function isMicrosoftAuthDomain(url) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      return TRUSTED_MICROSOFT_DOMAINS.some(domain => {
        return hostname === domain || hostname.endsWith(`.${domain}`);
      });
    } catch {
      return false;
    }
  }

  /**
   * Check if a URL matches known ADFS patterns.
   * @param {string} url - URL to check.
   * @returns {boolean}
   */
  function isAdfsDomain(url) {
    try {
      const parsed = new URL(url);
      const hostname = parsed.hostname.toLowerCase();
      return ADFS_PATTERNS.some(pattern => pattern.test(hostname));
    } catch {
      return false;
    }
  }

  /**
   * Sanitize a URL for safe logging (strip query params with tokens).
   * @param {string} url - URL to sanitize.
   * @returns {string}
   */
  function sanitizeUrlForLogging(url) {
    try {
      const parsed = new URL(url);
      const sensitiveParams = [
        'code', 'token', 'id_token', 'access_token', 'refresh_token',
        'session_state', 'nonce', 'state', 'SAMLResponse', 'SAMLRequest',
        'wresult', 'wctx'
      ];
      for (const param of sensitiveParams) {
        if (parsed.searchParams.has(param)) {
          parsed.searchParams.set(param, '[REDACTED]');
        }
      }
      return parsed.toString();
    } catch {
      return '[INVALID_URL]';
    }
  }

  return Object.freeze({
    TRUSTED_MICROSOFT_DOMAINS,
    VALID_RP_IDS,

    validateOrigin,
    validateRpId,
    validateSigningRequest,
    isMicrosoftAuthDomain,
    isAdfsDomain,
    sanitizeUrlForLogging
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.SecurityValidator = SecurityValidator;
}
