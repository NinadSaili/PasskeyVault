/**
 * AttestationBuilder - WebAuthn attestation object construction.
 *
 * Builds standards-compliant attestation objects with:
 *   - CBOR-encoded COSE public keys
 *   - Proper authenticatorData with attested credential data
 *   - Packed self-attestation (signed by credential key)
 *   - Full packed attestation with self-signed X.509 certificate
 *
 * Depends on: CborEncoder, CryptoEngine
 */
const AttestationBuilder = (() => {
  'use strict';

  // PasskeyVault AAGUID (fixed identifier for this authenticator)
  const AAGUID = new Uint8Array([
    0x50, 0x4b, 0x56, 0x2d, 0x45, 0x58, 0x54, 0x2d,
    0x41, 0x55, 0x54, 0x48, 0x2d, 0x56, 0x31, 0x00
  ]);

  const FLAGS = {
    UP: 0x01,   // User Present
    UV: 0x04,   // User Verified
    AT: 0x40,   // Attested Credential Data
    ED: 0x80    // Extension Data
  };

  // =============================================
  //  COSE Public Key Encoding
  // =============================================

  /**
   * Encode a public key as a CBOR-encoded COSE_Key (EC2, P-256, ES256).
   * @param {ArrayBuffer} spkiBytes - SPKI-encoded public key.
   * @returns {Promise<Uint8Array>} CBOR-encoded COSE key.
   */
  async function encodeCosePublicKey(spkiBytes) {
    const key = await crypto.subtle.importKey(
      'spki', spkiBytes,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true, ['verify']
    );
    const jwk = await crypto.subtle.exportKey('jwk', key);

    const x = new Uint8Array(CryptoEngine.base64UrlDecode(jwk.x));
    const y = new Uint8Array(CryptoEngine.base64UrlDecode(jwk.y));

    // COSE_Key Map: {1:2, 3:-7, -1:1, -2:x, -3:y}
    const coseMap = new Map();
    coseMap.set(1, 2);               // kty: EC2
    coseMap.set(3, -7);              // alg: ES256
    coseMap.set(-1, 1);              // crv: P-256
    coseMap.set(-2, x);              // x-coordinate (32 bytes)
    coseMap.set(-3, y);              // y-coordinate (32 bytes)

    return CborEncoder.encode(coseMap);
  }

  // =============================================
  //  Authenticator Data
  // =============================================

  /**
   * Build authenticatorData for assertion (no attested credential data).
   * @param {string} rpId - Relying party identifier.
   * @param {number} flags - Authenticator flags byte.
   * @param {number} signCount - Signature counter.
   * @returns {Promise<Uint8Array>} 37-byte authenticator data.
   */
  async function buildAuthData(rpId, flags, signCount) {
    const rpIdHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
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
   * Build authenticatorData with attested credential data (for registration).
   * @param {string} rpId - Relying party identifier.
   * @param {Uint8Array} credentialId - Raw credential ID bytes.
   * @param {ArrayBuffer} publicKeySpki - SPKI-encoded public key.
   * @returns {Promise<Uint8Array>} Full authenticator data.
   */
  async function buildRegistrationAuthData(rpId, credentialId, publicKeySpki) {
    const rpIdHash = new Uint8Array(
      await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
    );

    const coseKey = await encodeCosePublicKey(publicKeySpki);

    // attestedCredentialData: aaguid(16) + credIdLen(2) + credId(N) + coseKey(M)
    const attestedLen = 16 + 2 + credentialId.length + coseKey.length;
    const authData = new Uint8Array(37 + attestedLen);

    // rpIdHash (32 bytes)
    authData.set(rpIdHash, 0);
    // flags: UP + UV + AT
    authData[32] = FLAGS.UP | FLAGS.UV | FLAGS.AT;
    // signCount = 0 for registration
    authData[33] = 0; authData[34] = 0; authData[35] = 0; authData[36] = 0;

    // Attested credential data
    let offset = 37;
    authData.set(AAGUID, offset); offset += 16;
    authData[offset] = (credentialId.length >> 8) & 0xff;
    authData[offset + 1] = credentialId.length & 0xff;
    offset += 2;
    authData.set(credentialId, offset); offset += credentialId.length;
    authData.set(coseKey, offset);

    return authData;
  }

  // =============================================
  //  Packed Attestation (Self-Attestation)
  // =============================================

  /**
   * Build a CBOR-encoded packed self-attestation object.
   * The credential's own private key signs the attestation.
   * No x5c certificate chain - the RP verifies using the credential public key.
   *
   * @param {object} params
   * @param {string} params.rpId - Relying party ID.
   * @param {Uint8Array} params.credentialId - Raw credential ID.
   * @param {ArrayBuffer} params.publicKeySpki - SPKI public key.
   * @param {CryptoKey} params.privateKey - Credential private key (CryptoKey).
   * @param {ArrayBuffer} params.clientDataHash - SHA-256 of clientDataJSON.
   * @returns {Promise<Uint8Array>} CBOR-encoded attestation object.
   */
  async function buildSelfAttestation(params) {
    const { rpId, credentialId, publicKeySpki, privateKey, clientDataHash } = params;

    const authData = await buildRegistrationAuthData(rpId, credentialId, publicKeySpki);

    // Sign authData || clientDataHash
    const signedData = _concat(authData, new Uint8Array(clientDataHash));
    const rawSig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      signedData
    );
    const derSig = _ecdsaToDer(new Uint8Array(rawSig));

    // Attestation statement
    const attStmtMap = new Map();
    attStmtMap.set('alg', -7);
    attStmtMap.set('sig', derSig);

    // Full attestation object
    const attestationObject = {
      authData: authData,
      fmt: 'packed',
      attStmt: CborEncoder.encode(attStmtMap)
    };

    // Encode the whole attestation object as CBOR
    // We need a custom encoding since attStmt is already CBOR-encoded
    // Actually, we should let CborEncoder handle the nested map directly
    return _encodeAttestationObject(authData, 'packed', attStmtMap);
  }

  // =============================================
  //  Packed Attestation (Full, with X.509 cert)
  // =============================================

  /**
   * Build a CBOR-encoded packed attestation with self-signed X.509 certificate.
   *
   * @param {object} params
   * @param {string} params.rpId - Relying party ID.
   * @param {Uint8Array} params.credentialId - Raw credential ID.
   * @param {ArrayBuffer} params.publicKeySpki - Credential SPKI public key.
   * @param {CryptoKey} params.attestPrivateKey - Attestation private key (CryptoKey).
   * @param {Uint8Array} params.attestCertDer - DER-encoded X.509 attestation certificate.
   * @param {ArrayBuffer} params.clientDataHash - SHA-256 of clientDataJSON.
   * @returns {Promise<Uint8Array>} CBOR-encoded attestation object.
   */
  async function buildFullAttestation(params) {
    const { rpId, credentialId, publicKeySpki, attestPrivateKey, attestCertDer, clientDataHash } = params;

    const authData = await buildRegistrationAuthData(rpId, credentialId, publicKeySpki);

    const signedData = _concat(authData, new Uint8Array(clientDataHash));
    const rawSig = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      attestPrivateKey,
      signedData
    );
    const derSig = _ecdsaToDer(new Uint8Array(rawSig));

    const attStmtMap = new Map();
    attStmtMap.set('alg', -7);
    attStmtMap.set('sig', derSig);
    attStmtMap.set('x5c', [attestCertDer]);

    return _encodeAttestationObject(authData, 'packed', attStmtMap);
  }

  // =============================================
  //  X.509 Self-Signed Certificate Generation
  // =============================================

  /**
   * Generate a self-signed X.509 v3 attestation certificate.
   * @param {CryptoKeyPair} keyPair - ECDSA P-256 key pair.
   * @param {string} [cn='PasskeyVault Authenticator'] - Certificate CN.
   * @returns {Promise<Uint8Array>} DER-encoded X.509 certificate.
   */
  async function generateAttestationCert(keyPair, cn) {
    cn = cn || 'PasskeyVault Authenticator';

    // Export public key as SPKI for the certificate
    const spkiBytes = await crypto.subtle.exportKey('spki', keyPair.publicKey);

    // Build TBSCertificate
    const tbsCert = _derSequence(
      // version [0] EXPLICIT INTEGER (v3 = 2)
      _derExplicit(0, _derInteger(2)),
      // serialNumber (random 16 bytes)
      _derInteger(CryptoEngine.getRandomBytes(16)),
      // signature algorithm: ecdsaWithSHA256 (1.2.840.10045.4.3.2)
      _ecdsaSha256AlgId(),
      // issuer: CN=<cn>
      _derSequence(_derSet(_derSequence(
        _derOid([2, 5, 4, 3]),
        _derUtf8String(cn)
      ))),
      // validity: now to +10 years
      _derSequence(
        _derGeneralizedTime(new Date()),
        _derGeneralizedTime(new Date(Date.now() + 10 * 365.25 * 24 * 3600 * 1000))
      ),
      // subject: CN=<cn>
      _derSequence(_derSet(_derSequence(
        _derOid([2, 5, 4, 3]),
        _derUtf8String(cn)
      ))),
      // subjectPublicKeyInfo (from SPKI export)
      new Uint8Array(spkiBytes)
    );

    // Sign TBSCertificate
    const tbsSignature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      keyPair.privateKey,
      tbsCert
    );
    const derTbsSig = _ecdsaToDer(new Uint8Array(tbsSignature));

    // Build Certificate
    return _derSequence(
      tbsCert,
      _ecdsaSha256AlgId(),
      _derBitString(derTbsSig)
    );
  }

  /**
   * Generate a fresh attestation key pair and self-signed certificate.
   * @returns {Promise<{privateKey: ArrayBuffer, certificate: Uint8Array, keyPair: CryptoKeyPair}>}
   */
  async function generateAttestationMaterial() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const certificate = await generateAttestationCert(keyPair);
    const privateKeyPkcs8 = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    return { privateKey: privateKeyPkcs8, certificate, keyPair };
  }

  // =============================================
  //  Internal: CBOR Attestation Encoding
  // =============================================

  /**
   * Encode the complete attestation object as CBOR.
   * Uses specific key ordering per WebAuthn spec.
   */
  function _encodeAttestationObject(authData, fmt, attStmtMap) {
    // The attestation object is a CBOR map with string keys
    // Keys should be in the order: "fmt", "attStmt", "authData"
    // (canonical CBOR sorts by encoded key length, then lexicographically)
    // "fmt" (3 chars), "attStmt" (7 chars), "authData" (8 chars)
    const parts = [];

    // Map header: 3 items
    parts.push(new Uint8Array([0xa3]));

    // "fmt" => string
    parts.push(CborEncoder.encode('fmt'));
    parts.push(CborEncoder.encode(fmt));

    // "attStmt" => map
    parts.push(CborEncoder.encode('attStmt'));
    parts.push(CborEncoder.encode(attStmtMap));

    // "authData" => byte string
    parts.push(CborEncoder.encode('authData'));
    parts.push(CborEncoder.encode(authData));

    return _concatAll(parts);
  }

  // =============================================
  //  Internal: ASN.1 DER Encoding
  // =============================================

  function _derWrap(tag, content) {
    const lenBytes = _derLength(content.length);
    const result = new Uint8Array(1 + lenBytes.length + content.length);
    result[0] = tag;
    result.set(lenBytes, 1);
    result.set(content, 1 + lenBytes.length);
    return result;
  }

  function _derLength(len) {
    if (len < 128) return new Uint8Array([len]);
    if (len < 256) return new Uint8Array([0x81, len]);
    return new Uint8Array([0x82, (len >> 8) & 0xff, len & 0xff]);
  }

  function _derSequence(...items) {
    return _derWrap(0x30, _concatAll(items));
  }

  function _derSet(...items) {
    return _derWrap(0x31, _concatAll(items));
  }

  function _derInteger(value) {
    if (value instanceof Uint8Array) {
      // Big integer from bytes
      let data = value;
      let start = 0;
      while (start < data.length - 1 && data[start] === 0) start++;
      data = data.slice(start);
      if (data[0] & 0x80) {
        const padded = new Uint8Array(data.length + 1);
        padded[0] = 0;
        padded.set(data, 1);
        data = padded;
      }
      return _derWrap(0x02, data);
    }
    // Small integer
    if (value === 0) return _derWrap(0x02, new Uint8Array([0]));
    const bytes = [];
    let v = value;
    while (v > 0) {
      bytes.unshift(v & 0xff);
      v = v >>> 8;
    }
    if (bytes[0] & 0x80) bytes.unshift(0);
    return _derWrap(0x02, new Uint8Array(bytes));
  }

  function _derBitString(bytes) {
    const content = new Uint8Array(bytes.length + 1);
    content[0] = 0; // unused bits
    content.set(bytes, 1);
    return _derWrap(0x03, content);
  }

  function _derOid(oid) {
    const bytes = [];
    bytes.push(oid[0] * 40 + oid[1]);
    for (let i = 2; i < oid.length; i++) {
      let v = oid[i];
      if (v < 128) {
        bytes.push(v);
      } else {
        const parts = [];
        while (v > 0) {
          parts.unshift(v & 0x7f);
          v = v >>> 7;
        }
        for (let j = 0; j < parts.length - 1; j++) {
          bytes.push(parts[j] | 0x80);
        }
        bytes.push(parts[parts.length - 1]);
      }
    }
    return _derWrap(0x06, new Uint8Array(bytes));
  }

  function _derUtf8String(str) {
    return _derWrap(0x0c, new TextEncoder().encode(str));
  }

  function _derExplicit(tag, content) {
    return _derWrap(0xa0 | tag, content);
  }

  function _derNull() {
    return new Uint8Array([0x05, 0x00]);
  }

  /**
   * Encode GeneralizedTime (YYYYMMDDHHmmssZ).
   */
  function _derGeneralizedTime(date) {
    const pad = (n) => String(n).padStart(2, '0');
    const str = date.getUTCFullYear().toString() +
      pad(date.getUTCMonth() + 1) +
      pad(date.getUTCDate()) +
      pad(date.getUTCHours()) +
      pad(date.getUTCMinutes()) +
      pad(date.getUTCSeconds()) + 'Z';
    return _derWrap(0x18, new TextEncoder().encode(str));
  }

  /**
   * AlgorithmIdentifier for ecdsaWithSHA256.
   * OID: 1.2.840.10045.4.3.2
   */
  function _ecdsaSha256AlgId() {
    return _derSequence(
      _derOid([1, 2, 840, 10045, 4, 3, 2])
    );
  }

  // =============================================
  //  Internal: ECDSA Signature Conversion
  // =============================================

  /**
   * Convert WebCrypto ECDSA P1363 signature to DER format.
   */
  function _ecdsaToDer(p1363) {
    const halfLen = p1363.length / 2;
    const r = p1363.slice(0, halfLen);
    const s = p1363.slice(halfLen);

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

  // =============================================
  //  Internal: Buffer Utilities
  // =============================================

  function _concat(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }

  function _concatAll(arrays) {
    let totalLen = 0;
    for (const a of arrays) totalLen += a.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of arrays) {
      result.set(a, offset);
      offset += a.length;
    }
    return result;
  }

  return Object.freeze({
    AAGUID,
    FLAGS,
    encodeCosePublicKey,
    buildAuthData,
    buildRegistrationAuthData,
    buildSelfAttestation,
    buildFullAttestation,
    generateAttestationCert,
    generateAttestationMaterial
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.AttestationBuilder = AttestationBuilder;
}
