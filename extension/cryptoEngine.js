/**
 * CryptoEngine - Cryptographic operations for PasskeyVault.
 *
 * All cryptographic operations use the Web Crypto API exclusively.
 * Handles vault key derivation, AES-256-GCM encryption/decryption,
 * and WebAuthn-compatible P-256 key pair generation.
 */

const CryptoEngine = (() => {
  'use strict';

  const PBKDF2_ITERATIONS = 600000;
  const SALT_LENGTH = 32;
  const IV_LENGTH = 12;
  const AES_KEY_LENGTH = 256;
  const EC_CURVE = 'P-256';

  /**
   * Generate cryptographically secure random bytes.
   * @param {number} length - Number of bytes to generate.
   * @returns {Uint8Array}
   */
  function getRandomBytes(length) {
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    return buffer;
  }

  /**
   * Derive an AES-256-GCM key from a user PIN using PBKDF2.
   * @param {string} pin - User-provided PIN or passphrase.
   * @param {Uint8Array} salt - PBKDF2 salt (must be stored alongside vault).
   * @returns {Promise<CryptoKey>}
   */
  async function deriveVaultKey(pin, salt) {
    if (!pin || typeof pin !== 'string') {
      throw new Error('PIN is required for key derivation');
    }
    if (!(salt instanceof Uint8Array) || salt.length < SALT_LENGTH) {
      throw new Error(`Salt must be at least ${SALT_LENGTH} bytes`);
    }

    const encoder = new TextEncoder();
    const pinMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(pin),
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      pinMaterial,
      { name: 'AES-GCM', length: AES_KEY_LENGTH },
      false,
      ['encrypt', 'decrypt']
    );
  }

  /**
   * Encrypt plaintext using AES-256-GCM.
   * Returns an object containing the IV and ciphertext, both as Uint8Arrays.
   * @param {CryptoKey} key - AES-GCM key from deriveVaultKey.
   * @param {Uint8Array} plaintext - Data to encrypt.
   * @returns {Promise<{iv: Uint8Array, ciphertext: Uint8Array}>}
   */
  async function encrypt(key, plaintext) {
    const iv = getRandomBytes(IV_LENGTH);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      plaintext
    );
    return { iv, ciphertext: new Uint8Array(ciphertext) };
  }

  /**
   * Decrypt ciphertext using AES-256-GCM.
   * @param {CryptoKey} key - AES-GCM key from deriveVaultKey.
   * @param {Uint8Array} iv - Initialization vector used during encryption.
   * @param {Uint8Array} ciphertext - Data to decrypt.
   * @returns {Promise<Uint8Array>}
   */
  async function decrypt(key, iv, ciphertext) {
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        ciphertext
      );
      return new Uint8Array(plaintext);
    } catch {
      throw new Error('Decryption failed: invalid key or tampered data');
    }
  }

  /**
   * Encrypt a string and return a serializable object (base64-encoded fields).
   * @param {CryptoKey} key - AES-GCM key.
   * @param {string} plaintext - String to encrypt.
   * @returns {Promise<{iv: string, data: string}>}
   */
  async function encryptString(key, plaintext) {
    const encoder = new TextEncoder();
    const { iv, ciphertext } = await encrypt(key, encoder.encode(plaintext));
    return {
      iv: uint8ToBase64(iv),
      data: uint8ToBase64(ciphertext)
    };
  }

  /**
   * Decrypt a base64-encoded encrypted object back to a string.
   * @param {CryptoKey} key - AES-GCM key.
   * @param {{iv: string, data: string}} encrypted - Encrypted object from encryptString.
   * @returns {Promise<string>}
   */
  async function decryptString(key, encrypted) {
    const iv = base64ToUint8(encrypted.iv);
    const ciphertext = base64ToUint8(encrypted.data);
    const plaintext = await decrypt(key, iv, ciphertext);
    return new TextDecoder().decode(plaintext);
  }

  /**
   * Generate a WebAuthn-compatible ECDSA P-256 key pair.
   * The private key is exported as PKCS8 for encrypted storage.
   * The public key is exported as SPKI for verification.
   * @returns {Promise<{privateKey: ArrayBuffer, publicKey: ArrayBuffer, keyPair: CryptoKeyPair}>}
   */
  async function generateWebAuthnKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: EC_CURVE },
      true,
      ['sign', 'verify']
    );

    const privateKeyRaw = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const publicKeyRaw = await crypto.subtle.exportKey('spki', keyPair.publicKey);

    return {
      privateKey: privateKeyRaw,
      publicKey: publicKeyRaw,
      keyPair
    };
  }

  /**
   * Import a private key from PKCS8 bytes for signing.
   * @param {ArrayBuffer} pkcs8Bytes - PKCS8-encoded private key.
   * @returns {Promise<CryptoKey>}
   */
  async function importPrivateKey(pkcs8Bytes) {
    return crypto.subtle.importKey(
      'pkcs8',
      pkcs8Bytes,
      { name: 'ECDSA', namedCurve: EC_CURVE },
      false,
      ['sign']
    );
  }

  /**
   * Import a public key from SPKI bytes for verification.
   * @param {ArrayBuffer} spkiBytes - SPKI-encoded public key.
   * @returns {Promise<CryptoKey>}
   */
  async function importPublicKey(spkiBytes) {
    return crypto.subtle.importKey(
      'spki',
      spkiBytes,
      { name: 'ECDSA', namedCurve: EC_CURVE },
      false,
      ['verify']
    );
  }

  /**
   * Sign data using ECDSA with SHA-256.
   * @param {CryptoKey} privateKey - ECDSA private key.
   * @param {ArrayBuffer} data - Data to sign.
   * @returns {Promise<ArrayBuffer>}
   */
  async function sign(privateKey, data) {
    return crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      privateKey,
      data
    );
  }

  /**
   * Verify an ECDSA signature.
   * @param {CryptoKey} publicKey - ECDSA public key.
   * @param {ArrayBuffer} signature - Signature to verify.
   * @param {ArrayBuffer} data - Original signed data.
   * @returns {Promise<boolean>}
   */
  async function verify(publicKey, signature, data) {
    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      signature,
      data
    );
  }

  /**
   * Compute SHA-256 hash of data.
   * @param {ArrayBuffer} data - Data to hash.
   * @returns {Promise<ArrayBuffer>}
   */
  async function sha256(data) {
    return crypto.subtle.digest('SHA-256', data);
  }

  /**
   * Generate a random credential ID (32 bytes).
   * @returns {Uint8Array}
   */
  function generateCredentialId() {
    return getRandomBytes(32);
  }

  // --- Encoding Utilities ---

  function uint8ToBase64(uint8Array) {
    let binary = '';
    for (let i = 0; i < uint8Array.length; i++) {
      binary += String.fromCharCode(uint8Array[i]);
    }
    return btoa(binary);
  }

  function base64ToUint8(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function arrayBufferToBase64(buffer) {
    return uint8ToBase64(new Uint8Array(buffer));
  }

  function base64ToArrayBuffer(base64) {
    return base64ToUint8(base64).buffer;
  }

  function base64UrlEncode(buffer) {
    return arrayBufferToBase64(buffer)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  function base64UrlDecode(base64url) {
    let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    return base64ToArrayBuffer(base64);
  }

  return Object.freeze({
    PBKDF2_ITERATIONS,
    SALT_LENGTH,
    IV_LENGTH,

    getRandomBytes,
    deriveVaultKey,
    encrypt,
    decrypt,
    encryptString,
    decryptString,
    generateWebAuthnKeyPair,
    importPrivateKey,
    importPublicKey,
    sign,
    verify,
    sha256,
    generateCredentialId,

    uint8ToBase64,
    base64ToUint8,
    arrayBufferToBase64,
    base64ToArrayBuffer,
    base64UrlEncode,
    base64UrlDecode
  });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.CryptoEngine = CryptoEngine;
}
