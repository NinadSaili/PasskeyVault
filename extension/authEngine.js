/**
 * AuthEngine - WebAuthn key generation and authentication challenge signing.
 *
 * Handles the full WebAuthn flow:
 *   1. Generate P-256 key pairs for passkey registration.
 *   2. Build standards-compliant CBOR attestation objects.
 *   3. Sign WebAuthn challenges using stored passkeys.
 *   4. Produce correctly formatted authenticator assertions.
 *
 * Depends on: CryptoEngine, VaultEngine, SecurityValidator,
 *             CborEncoder, AttestationBuilder
 */
const AuthEngine = (() => {
  'use strict';

  /**
   * Register a new passkey for a user and relying party.
   * Produces a CBOR-encoded packed self-attestation object.
   *
   * @param {object} params
   * @param {string} params.rpId - Relying party ID.
   * @param {string} params.rpName - Relying party display name.
   * @param {string} params.userId - Vault user ID.
   * @param {string} params.userName - User display name.
   * @param {ArrayBuffer} [params.clientDataHash] - Hash of clientDataJSON (for content script flow).
   * @returns {Promise<object>} Registration result with attestationObject.
   */
  async function registerPasskey({ rpId, rpName, userId, userName, clientDataHash }) {
    if (!rpId || !userId) {
      throw new Error('rpId and userId are required for registration');
    }
    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked to register a passkey');
    }

    // Validate RP ID
    if (typeof SecurityValidator !== 'undefined') {
      const rpValidation = SecurityValidator.validateRpId(rpId, `https://${rpId}`);
      if (!rpValidation.valid) {
        throw new Error(`RP ID validation failed: ${rpValidation.reason}`);
      }
    }

    // Generate WebAuthn-compatible P-256 key pair (keep CryptoKeyPair for attestation signing)
    const { privateKey, publicKey, keyPair } = await CryptoEngine.generateWebAuthnKeyPair();
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

    // If no clientDataHash provided (popup registration), create a synthetic one
    if (!clientDataHash) {
      const syntheticClientData = JSON.stringify({
        type: 'webauthn.create',
        challenge: CryptoEngine.base64UrlEncode(CryptoEngine.getRandomBytes(32)),
        origin: `https://${rpId}`,
        crossOrigin: false
      });
      clientDataHash = await CryptoEngine.sha256(
        new TextEncoder().encode(syntheticClientData)
      );
    }

    // Build CBOR-encoded packed self-attestation object
    const attestationObjectBytes = await AttestationBuilder.buildSelfAttestation({
      rpId,
      credentialId,
      publicKeySpki: publicKey,
      privateKey: keyPair.privateKey,
      clientDataHash
    });

    // COSE public key (for RP verification)
    const cosePublicKey = await AttestationBuilder.encodeCosePublicKey(publicKey);

    return {
      credentialId: storedCredId,
      credentialIdRaw: CryptoEngine.base64UrlEncode(credentialId),
      publicKey: CryptoEngine.arrayBufferToBase64(publicKey),
      publicKeyCose: CryptoEngine.base64UrlEncode(cosePublicKey),
      attestationObject: CryptoEngine.base64UrlEncode(attestationObjectBytes),
      rpId,
      userId,
      type: 'public-key',
      transports: ['internal']
    };
  }

  /**
   * Register a passkey via content script WebAuthn interception.
   * Called when navigator.credentials.create() is intercepted.
   *
   * @param {object} params
   * @param {string} params.rpId - Relying party ID.
   * @param {string} params.rpName - RP display name.
   * @param {object} params.user - {id, name, displayName} from WebAuthn options.
   * @param {string} params.challenge - Base64url challenge from the RP.
   * @param {string} params.origin - Page origin.
   * @returns {Promise<object>} Full registration response for content script.
   */
  async function registerFromWebAuthn({ rpId, rpName, user, challenge, origin }) {
    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked');
    }

    // Security validation
    if (typeof SecurityValidator !== 'undefined' && origin) {
      const originCheck = SecurityValidator.validateOrigin(origin);
      if (!originCheck.valid) {
        throw new Error(`Origin validation failed: ${originCheck.reason}`);
      }
    }

    // Add user to vault if not exists
    const vaultUserId = await VaultEngine.addUser({
      displayName: user.displayName || user.name,
      entraUpn: user.name
    });

    // Build clientDataJSON and hash (matching what the browser would produce)
    const clientDataJSON = JSON.stringify({
      type: 'webauthn.create',
      challenge: challenge,
      origin: origin,
      crossOrigin: false
    });
    const clientDataHash = await CryptoEngine.sha256(
      new TextEncoder().encode(clientDataJSON)
    );

    // Generate keys and build attestation
    const { privateKey, publicKey, keyPair } = await CryptoEngine.generateWebAuthnKeyPair();
    const credentialId = CryptoEngine.generateCredentialId();

    const storedCredId = await VaultEngine.storePasskey({
      rpId,
      rpName: rpName || rpId,
      userId: vaultUserId,
      privateKey,
      publicKey,
      credentialId
    });

    const attestationObjectBytes = await AttestationBuilder.buildSelfAttestation({
      rpId,
      credentialId,
      publicKeySpki: publicKey,
      privateKey: keyPair.privateKey,
      clientDataHash
    });

    return {
      credentialId: storedCredId,
      credentialIdRaw: CryptoEngine.base64UrlEncode(credentialId),
      attestationObject: CryptoEngine.base64UrlEncode(attestationObjectBytes),
      clientDataJSON: CryptoEngine.base64UrlEncode(
        new TextEncoder().encode(clientDataJSON)
      ),
      publicKeySpki: CryptoEngine.base64UrlEncode(new Uint8Array(publicKey)),
      publicKeyAlgorithm: -7,
      transports: ['internal'],
      type: 'public-key'
    };
  }

  /**
   * Sign a WebAuthn authentication challenge using a stored passkey.
   * Uses AttestationBuilder for proper authenticator data construction.
   */
  async function signChallenge({ credentialId, rpId, challenge, origin, userVerification = true }) {
    if (!credentialId || !rpId || !challenge) {
      throw new Error('credentialId, rpId, and challenge are required');
    }
    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked to sign challenges');
    }

    // Security validation
    if (typeof SecurityValidator !== 'undefined' && origin) {
      const originCheck = SecurityValidator.validateOrigin(origin);
      if (!originCheck.valid) {
        throw new Error(`Origin validation failed: ${originCheck.reason}`);
      }
      const rpCheck = SecurityValidator.validateRpId(rpId, origin);
      if (!rpCheck.valid) {
        throw new Error(`RP ID validation failed: ${rpCheck.reason}`);
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
      const flags = AttestationBuilder.FLAGS.UP | (userVerification ? AttestationBuilder.FLAGS.UV : 0);

      // Use AttestationBuilder for proper authenticator data
      const authenticatorData = await AttestationBuilder.buildAuthData(rpId, flags, signCount);

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

  /**
   * Get available passkeys for a given RP ID.
   */
  function getAvailablePasskeys(rpId, allowCredentials) {
    if (!VaultEngine.isUnlocked()) return [];
    let passkeys = VaultEngine.getPasskeysByRpId(rpId);
    if (allowCredentials && allowCredentials.length > 0) {
      const allowedIds = new Set(allowCredentials.map(c => c.id));
      passkeys = passkeys.filter(p => allowedIds.has(p.credentialId));
    }
    return passkeys.map(({ encryptedPrivateKey, ...rest }) => rest);
  }

  /**
   * Verify a signature using the stored public key.
   */
  async function verifySignature(credentialId, signature, data) {
    const passkey = VaultEngine.getPasskey(credentialId);
    if (!passkey) return false;
    const publicKeyBytes = CryptoEngine.base64ToArrayBuffer(passkey.publicKey);
    const publicKey = await CryptoEngine.importPublicKey(publicKeyBytes);
    return CryptoEngine.verify(publicKey, signature, data);
  }

  // --- Internal helpers ---

  function _ecdsaSignatureToDer(p1363Sig) {
    const halfLen = p1363Sig.length / 2;
    const r = p1363Sig.slice(0, halfLen);
    const s = p1363Sig.slice(halfLen);

    function intToDer(intBytes) {
      let start = 0;
      while (start < intBytes.length - 1 && intBytes[start] === 0) start++;
      let trimmed = intBytes.slice(start);
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
    der[offset++] = 0x30;
    der[offset++] = seqLen;
    der[offset++] = 0x02;
    der[offset++] = rDer.length;
    der.set(rDer, offset); offset += rDer.length;
    der[offset++] = 0x02;
    der[offset++] = sDer.length;
    der.set(sDer, offset);
    return der;
  }

  function _concatenateBuffers(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }

  return Object.freeze({
    registerPasskey,
    registerFromWebAuthn,
    signChallenge,
    getAvailablePasskeys,
    verifySignature
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.AuthEngine = AuthEngine;
}
