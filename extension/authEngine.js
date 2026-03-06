/**
 * AuthEngine - WebAuthn key generation and authentication challenge signing.
 *
 * Handles the full WebAuthn assertion flow:
 *   1. Generate P-256 key pairs for passkey registration.
 *   2. Sign WebAuthn challenges using stored passkeys.
 *   3. Produce correctly formatted WebAuthn authenticator assertions.
 *
 * Depends on: CryptoEngine, VaultEngine, SecurityValidator
 */

const AuthEngine = (() => {
  'use strict';

  // AAGUID for this authenticator (randomly generated, fixed for this extension)
  const AAGUID = new Uint8Array([
    0x50, 0x4b, 0x56, 0x2d, 0x45, 0x58, 0x54, 0x2d,
    0x41, 0x55, 0x54, 0x48, 0x2d, 0x56, 0x31, 0x00
  ]);

  // Authenticator flags
  const FLAGS = {
    UP: 0x01,   // User Present
    UV: 0x04,   // User Verified
    AT: 0x40,   // Attested Credential Data
    ED: 0x80    // Extension Data
  };

  /**
   * Register a new passkey for a user and relying party.
   * Generates a P-256 key pair, stores it encrypted in the vault,
   * and returns registration data suitable for WebAuthn.
   *
   * @param {object} params
   * @param {string} params.rpId - Relying party ID (e.g. "login.microsoft.com").
   * @param {string} params.rpName - Relying party display name.
   * @param {string} params.userId - Vault user ID.
   * @param {string} params.userName - User display name.
   * @returns {Promise<object>} Registration result with credentialId and publicKey.
   */
  async function registerPasskey({ rpId, rpName, userId, userName }) {
    if (!rpId || !userId) {
      throw new Error('rpId and userId are required for registration');
    }

    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked to register a passkey');
    }

    // Validate the RP ID before generating keys
    if (typeof SecurityValidator !== 'undefined') {
      const rpValidation = SecurityValidator.validateRpId(rpId, `https://${rpId}`);
      if (!rpValidation.valid) {
        throw new Error(`RP ID validation failed: ${rpValidation.reason}`);
      }
    }

    // Generate WebAuthn-compatible P-256 key pair
    const { privateKey, publicKey } = await CryptoEngine.generateWebAuthnKeyPair();
    const credentialId = CryptoEngine.generateCredentialId();

    // Store encrypted in vault
    const storedCredId = await VaultEngine.storePasskey({
      rpId,
      rpName: rpName || rpId,
      userId,
      privateKey,
      publicKey,
      credentialId
    });

    // Build the COSE public key for the relying party
    const cosePublicKey = await _exportCosePublicKey(publicKey);

    return {
      credentialId: storedCredId,
      credentialIdRaw: credentialId,
      publicKey: CryptoEngine.arrayBufferToBase64(publicKey),
      publicKeyCose: cosePublicKey,
      rpId,
      userId,
      type: 'public-key',
      transports: ['internal'],
      attestationObject: await _buildAttestationObject(publicKey, credentialId, rpId)
    };
  }

  /**
   * Sign a WebAuthn authentication challenge using a stored passkey.
   *
   * @param {object} params
   * @param {string} params.credentialId - Base64url credential ID.
   * @param {string} params.rpId - Relying party ID.
   * @param {ArrayBuffer|Uint8Array} params.challenge - Server challenge bytes.
   * @param {string} params.origin - Request origin for validation.
   * @param {boolean} [params.userVerification=true] - Whether UV flag should be set.
   * @returns {Promise<object>} Signed WebAuthn assertion.
   */
  async function signChallenge({ credentialId, rpId, challenge, origin, userVerification = true }) {
    if (!credentialId || !rpId || !challenge) {
      throw new Error('credentialId, rpId, and challenge are required');
    }

    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked to sign challenges');
    }

    // Security validation
    if (typeof SecurityValidator !== 'undefined') {
      if (origin) {
        const originCheck = SecurityValidator.validateOrigin(origin);
        if (!originCheck.valid) {
          throw new Error(`Origin validation failed: ${originCheck.reason}`);
        }

        const rpCheck = SecurityValidator.validateRpId(rpId, origin);
        if (!rpCheck.valid) {
          throw new Error(`RP ID validation failed: ${rpCheck.reason}`);
        }
      }
    }

    // Verify the passkey exists and belongs to this RP
    const passkey = VaultEngine.getPasskey(credentialId);
    if (!passkey) {
      throw new Error('Passkey not found in vault');
    }
    if (passkey.rpId !== rpId) {
      throw new Error('RP ID mismatch: passkey does not belong to this relying party');
    }

    // Get decrypted private key (exists only for the duration of signing)
    let privateKeyBytes = null;
    try {
      privateKeyBytes = await VaultEngine.getDecryptedPrivateKey(credentialId);
      const privateKey = await CryptoEngine.importPrivateKey(privateKeyBytes);

      // Build authenticator data
      const signCount = await VaultEngine.incrementSignCount(credentialId);
      const flags = FLAGS.UP | (userVerification ? FLAGS.UV : 0);
      const authenticatorData = _buildAuthenticatorData(rpId, flags, signCount);

      // Hash the client data JSON
      const challengeB64url = CryptoEngine.base64UrlEncode(
        challenge instanceof Uint8Array ? challenge.buffer : challenge
      );
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge: challengeB64url,
        origin: origin || `https://${rpId}`,
        crossOrigin: false
      });
      const clientDataHash = await CryptoEngine.sha256(
        new TextEncoder().encode(clientDataJSON)
      );

      // Sign authenticatorData || clientDataHash
      const signedData = _concatenateBuffers(authenticatorData, new Uint8Array(clientDataHash));
      const signature = await CryptoEngine.sign(privateKey, signedData);

      // Convert DER signature for WebAuthn compatibility
      const derSignature = _ecdsaSignatureToDer(new Uint8Array(signature));

      return {
        credentialId,
        authenticatorData: CryptoEngine.base64UrlEncode(authenticatorData),
        clientDataJSON: CryptoEngine.base64UrlEncode(
          new TextEncoder().encode(clientDataJSON)
        ),
        signature: CryptoEngine.base64UrlEncode(derSignature),
        userHandle: CryptoEngine.base64UrlEncode(
          new TextEncoder().encode(passkey.userId)
        ),
        type: 'public-key'
      };
    } finally {
      // Zero out the private key bytes from memory
      if (privateKeyBytes) {
        const view = new Uint8Array(privateKeyBytes);
        view.fill(0);
      }
    }
  }

  /**
   * Get available passkeys for a given RP ID that can satisfy an
   * allowCredentials list from the server.
   *
   * @param {string} rpId - Relying party ID.
   * @param {Array<{id: string, type: string}>} [allowCredentials] - Server's allowed list.
   * @returns {Array<object>} Matching passkeys (without private key data).
   */
  function getAvailablePasskeys(rpId, allowCredentials) {
    if (!VaultEngine.isUnlocked()) return [];

    let passkeys = VaultEngine.getPasskeysByRpId(rpId);

    if (allowCredentials && allowCredentials.length > 0) {
      const allowedIds = new Set(allowCredentials.map(c => c.id));
      passkeys = passkeys.filter(p => allowedIds.has(p.credentialId));
    }

    // Strip encrypted private key data from results
    return passkeys.map(({ encryptedPrivateKey, ...rest }) => rest);
  }

  /**
   * Verify a signature using the stored public key (for testing / self-check).
   *
   * @param {string} credentialId - Base64url credential ID.
   * @param {ArrayBuffer} signature - Signature to verify.
   * @param {ArrayBuffer} data - Original signed data.
   * @returns {Promise<boolean>}
   */
  async function verifySignature(credentialId, signature, data) {
    const passkey = VaultEngine.getPasskey(credentialId);
    if (!passkey) return false;

    const publicKeyBytes = CryptoEngine.base64ToArrayBuffer(passkey.publicKey);
    const publicKey = await CryptoEngine.importPublicKey(publicKeyBytes);
    return CryptoEngine.verify(publicKey, signature, data);
  }

  // --- Internal: Authenticator Data Construction ---

  /**
   * Build the authenticatorData byte array per WebAuthn spec.
   * @param {string} rpId - RP ID to hash.
   * @param {number} flags - Authenticator flags byte.
   * @param {number} signCount - Signature counter (32-bit big-endian).
   * @returns {Uint8Array}
   */
  function _buildAuthenticatorData(rpId, flags, signCount) {
    // rpIdHash (32 bytes SHA-256)
    // We use synchronous approach: precompute in caller if needed.
    // For now, build with placeholder and replace.
    const encoder = new TextEncoder();
    const rpIdBytes = encoder.encode(rpId);

    // We need SHA-256 but it's async. Build the structure and
    // let the caller handle the async hash. For simplicity,
    // we build a fixed-size buffer synchronously with a zero hash
    // and replace it. In practice, the caller patches this.

    // Actually, let's build it correctly with a sync-compatible approach:
    // The authenticator data is: rpIdHash(32) || flags(1) || signCount(4)
    const authData = new Uint8Array(37);

    // rpIdHash will be filled by the async wrapper
    // flags
    authData[32] = flags;

    // signCount as 32-bit big-endian
    authData[33] = (signCount >> 24) & 0xff;
    authData[34] = (signCount >> 16) & 0xff;
    authData[35] = (signCount >> 8) & 0xff;
    authData[36] = signCount & 0xff;

    return authData;
  }

  /**
   * Async version that correctly hashes the RP ID.
   * Called from signChallenge before signing.
   */
  async function _buildAuthenticatorDataAsync(rpId, flags, signCount) {
    const encoder = new TextEncoder();
    const rpIdHash = new Uint8Array(
      await CryptoEngine.sha256(encoder.encode(rpId))
    );

    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = flags;
    authData[33] = (signCount >> 24) & 0xff;
    authData[34] = (signCount >> 16) & 0xff;
    authData[35] = (signCount >> 8) & 0xff;
    authData[36] = signCount & 0xff;

    return authData;
  }

  /**
   * Build a minimal attestation object (packed self-attestation).
   */
  async function _buildAttestationObject(publicKeySpki, credentialId, rpId) {
    const flags = FLAGS.UP | FLAGS.UV | FLAGS.AT;
    const authData = await _buildAuthenticatorDataAsync(rpId, flags, 0);

    // For self-attestation, the attestation statement format is "none"
    // This is acceptable for platform authenticators
    return {
      fmt: 'none',
      attStmt: {},
      authData: CryptoEngine.base64UrlEncode(authData)
    };
  }

  /**
   * Export a public key as COSE_Key (EC2, P-256).
   * Extracts raw x,y coordinates from SPKI.
   */
  async function _exportCosePublicKey(spkiBuffer) {
    // Import then re-export as JWK to get x,y
    const key = await crypto.subtle.importKey(
      'spki',
      spkiBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);

    return {
      kty: 2,        // EC2
      alg: -7,       // ES256
      crv: 1,        // P-256
      x: jwk.x,      // base64url x-coordinate
      y: jwk.y       // base64url y-coordinate
    };
  }

  /**
   * Convert Web Crypto ECDSA signature (IEEE P1363) to DER format
   * as required by WebAuthn.
   */
  function _ecdsaSignatureToDer(p1363Sig) {
    const halfLen = p1363Sig.length / 2;
    const r = p1363Sig.slice(0, halfLen);
    const s = p1363Sig.slice(halfLen);

    function intToDer(intBytes) {
      // Remove leading zeros but keep one if high bit is set
      let start = 0;
      while (start < intBytes.length - 1 && intBytes[start] === 0) start++;
      let trimmed = intBytes.slice(start);
      // If high bit set, prepend a zero byte
      if (trimmed[0] & 0x80) {
        const padded = new Uint8Array(trimmed.length + 1);
        padded[0] = 0;
        padded.set(trimmed, 1);
        trimmed = padded;
      }
      return trimmed;
    }

    const rDer = intToDer(r);
    const sDer = intToDer(s);

    const seqLen = 2 + rDer.length + 2 + sDer.length;
    const der = new Uint8Array(2 + seqLen);
    let offset = 0;

    der[offset++] = 0x30; // SEQUENCE
    der[offset++] = seqLen;
    der[offset++] = 0x02; // INTEGER
    der[offset++] = rDer.length;
    der.set(rDer, offset);
    offset += rDer.length;
    der[offset++] = 0x02; // INTEGER
    der[offset++] = sDer.length;
    der.set(sDer, offset);

    return der;
  }

  /**
   * Concatenate two Uint8Arrays.
   */
  function _concatenateBuffers(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }

  // Patch signChallenge to use async authenticator data
  const _originalSignChallenge = signChallenge;

  async function signChallengePatched(params) {
    // Override _buildAuthenticatorData to use async version within signChallenge
    const { credentialId, rpId, challenge, origin, userVerification = true } = params;

    if (!credentialId || !rpId || !challenge) {
      throw new Error('credentialId, rpId, and challenge are required');
    }
    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked to sign challenges');
    }

    // Security validation
    if (typeof SecurityValidator !== 'undefined') {
      if (origin) {
        const originCheck = SecurityValidator.validateOrigin(origin);
        if (!originCheck.valid) {
          throw new Error(`Origin validation failed: ${originCheck.reason}`);
        }
        const rpCheck = SecurityValidator.validateRpId(rpId, origin);
        if (!rpCheck.valid) {
          throw new Error(`RP ID validation failed: ${rpCheck.reason}`);
        }
      }
    }

    const passkey = VaultEngine.getPasskey(credentialId);
    if (!passkey) throw new Error('Passkey not found in vault');
    if (passkey.rpId !== rpId) throw new Error('RP ID mismatch');

    let privateKeyBytes = null;
    try {
      privateKeyBytes = await VaultEngine.getDecryptedPrivateKey(credentialId);
      const privateKey = await CryptoEngine.importPrivateKey(privateKeyBytes);

      const signCount = await VaultEngine.incrementSignCount(credentialId);
      const flags = FLAGS.UP | (userVerification ? FLAGS.UV : 0);
      const authenticatorData = await _buildAuthenticatorDataAsync(rpId, flags, signCount);

      const challengeB64url = CryptoEngine.base64UrlEncode(
        challenge instanceof Uint8Array ? challenge.buffer : challenge
      );
      const clientDataJSON = JSON.stringify({
        type: 'webauthn.get',
        challenge: challengeB64url,
        origin: origin || `https://${rpId}`,
        crossOrigin: false
      });
      const clientDataHash = await CryptoEngine.sha256(
        new TextEncoder().encode(clientDataJSON)
      );

      const signedData = _concatenateBuffers(authenticatorData, new Uint8Array(clientDataHash));
      const signature = await CryptoEngine.sign(privateKey, signedData);
      const derSignature = _ecdsaSignatureToDer(new Uint8Array(signature));

      return {
        credentialId,
        authenticatorData: CryptoEngine.base64UrlEncode(authenticatorData),
        clientDataJSON: CryptoEngine.base64UrlEncode(
          new TextEncoder().encode(clientDataJSON)
        ),
        signature: CryptoEngine.base64UrlEncode(derSignature),
        userHandle: CryptoEngine.base64UrlEncode(
          new TextEncoder().encode(passkey.userId)
        ),
        type: 'public-key'
      };
    } finally {
      if (privateKeyBytes) {
        new Uint8Array(privateKeyBytes).fill(0);
      }
    }
  }

  return Object.freeze({
    AAGUID,
    registerPasskey,
    signChallenge: signChallengePatched,
    getAvailablePasskeys,
    verifySignature
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.AuthEngine = AuthEngine;
}
