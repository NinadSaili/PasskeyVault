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
   */
  async function registerPasskey({ rpId, rpName, userId, userName }) {
    if (!rpId || !userId) {
      throw new Error('rpId and userId are required for registration');
    }
    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked to register a passkey');
    }

    if (typeof SecurityValidator !== 'undefined') {
      const rpValidation = SecurityValidator.validateRpId(rpId, `https://${rpId}`);
      if (!rpValidation.valid) {
        throw new Error(`RP ID validation failed: ${rpValidation.reason}`);
      }
    }

    const { privateKey, publicKey } = await CryptoEngine.generateWebAuthnKeyPair();
    const credentialId = CryptoEngine.generateCredentialId();

    const storedCredId = await VaultEngine.storePasskey({
      rpId,
      rpName: rpName || rpId,
      userId,
      privateKey,
      publicKey,
      credentialId
    });

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
   */
  async function signChallenge({ credentialId, rpId, challenge, origin, userVerification = true }) {
    if (!credentialId || !rpId || !challenge) {
      throw new Error('credentialId, rpId, and challenge are required');
    }
    if (!VaultEngine.isUnlocked()) {
      throw new Error('Vault must be unlocked to sign challenges');
    }

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

  async function _buildAttestationObject(publicKeySpki, credentialId, rpId) {
    const flags = FLAGS.UP | FLAGS.UV | FLAGS.AT;
    const authData = await _buildAuthenticatorDataAsync(rpId, flags, 0);
    return {
      fmt: 'none',
      attStmt: {},
      authData: CryptoEngine.base64UrlEncode(authData)
    };
  }

  async function _exportCosePublicKey(spkiBuffer) {
    const key = await crypto.subtle.importKey(
      'spki',
      spkiBuffer,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);
    return {
      kty: 2,     // EC2
      alg: -7,    // ES256
      crv: 1,     // P-256
      x: jwk.x,
      y: jwk.y
    };
  }

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

  function _concatenateBuffers(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }

  return Object.freeze({
    AAGUID,
    registerPasskey,
    signChallenge,
    getAvailablePasskeys,
    verifySignature
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.AuthEngine = AuthEngine;
}
