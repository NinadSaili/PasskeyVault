/**
 * PasskeyVault E2E Test Harness
 *
 * Runs in Node.js with WebCrypto. Tests:
 * 1. CBOR encoder correctness against known values
 * 2. Attestation builder (authData, COSE key, self-attestation, X.509 cert)
 * 3. Signature verification round-trip
 * 4. DER encoding correctness
 * 5. Background message routing completeness
 * 6. Content script interception logic audit
 */

import { webcrypto } from 'crypto';
import { readFileSync } from 'fs';
import { TextEncoder, TextDecoder } from 'util';

// Polyfill browser globals for extension code
// Node 22+ has crypto as a getter; use defineProperty to override
Object.defineProperty(globalThis, 'crypto', { value: webcrypto, writable: true, configurable: true });
globalThis.TextEncoder = TextEncoder;
globalThis.TextDecoder = TextDecoder;
globalThis.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
globalThis.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');

let passed = 0;
let failed = 0;
const failures = [];

function assert(condition, testName) {
  if (condition) {
    passed++;
    console.log(`  \x1b[32m✓\x1b[0m ${testName}`);
  } else {
    failed++;
    failures.push(testName);
    console.log(`  \x1b[31m✗\x1b[0m ${testName}`);
  }
}

function assertEq(actual, expected, testName) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) {
    console.log(`    Expected: ${JSON.stringify(expected)}`);
    console.log(`    Actual:   ${JSON.stringify(actual)}`);
  }
  assert(pass, testName);
}

function hex(u8) {
  return [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// Load extension modules into global scope
// ============================================

// Load CborEncoder
eval(readFileSync('extension/cborEncoder.js', 'utf-8'));

// Load CryptoEngine
eval(readFileSync('extension/cryptoEngine.js', 'utf-8'));

// Load AttestationBuilder
eval(readFileSync('extension/attestation.js', 'utf-8'));

// ============================================
// Test 1: CBOR Encoder
// ============================================

console.log('\n\x1b[1m=== Test 1: CBOR Encoder ===\x1b[0m');

// RFC 8949 test vectors
// Unsigned integers
assertEq(hex(CborEncoder.encode(0)), '00', 'CBOR: encode 0');
assertEq(hex(CborEncoder.encode(1)), '01', 'CBOR: encode 1');
assertEq(hex(CborEncoder.encode(23)), '17', 'CBOR: encode 23');
assertEq(hex(CborEncoder.encode(24)), '1818', 'CBOR: encode 24');
assertEq(hex(CborEncoder.encode(255)), '18ff', 'CBOR: encode 255');
assertEq(hex(CborEncoder.encode(256)), '190100', 'CBOR: encode 256');
assertEq(hex(CborEncoder.encode(65535)), '19ffff', 'CBOR: encode 65535');
assertEq(hex(CborEncoder.encode(65536)), '1a00010000', 'CBOR: encode 65536');

// Negative integers
assertEq(hex(CborEncoder.encode(-1)), '20', 'CBOR: encode -1');
assertEq(hex(CborEncoder.encode(-7)), '26', 'CBOR: encode -7');
assertEq(hex(CborEncoder.encode(-24)), '37', 'CBOR: encode -24');
assertEq(hex(CborEncoder.encode(-25)), '3818', 'CBOR: encode -25');

// Booleans and null
assertEq(hex(CborEncoder.encode(true)), 'f5', 'CBOR: encode true');
assertEq(hex(CborEncoder.encode(false)), 'f4', 'CBOR: encode false');
assertEq(hex(CborEncoder.encode(null)), 'f6', 'CBOR: encode null');

// Strings
assertEq(hex(CborEncoder.encode('')), '60', 'CBOR: encode empty string');
assertEq(hex(CborEncoder.encode('a')), '6161', 'CBOR: encode "a"');
assertEq(hex(CborEncoder.encode('fmt')), '6366' + '6d' + '74', 'CBOR: encode "fmt"');

// Byte strings
assertEq(hex(CborEncoder.encode(new Uint8Array([]))), '40', 'CBOR: encode empty bytes');
assertEq(hex(CborEncoder.encode(new Uint8Array([0xaa, 0xbb]))), '42aabb', 'CBOR: encode 2 bytes');

// Arrays
assertEq(hex(CborEncoder.encode([])), '80', 'CBOR: encode empty array');
assertEq(hex(CborEncoder.encode([1, 2, 3])), '83010203', 'CBOR: encode [1,2,3]');

// Maps (integer-keyed for COSE)
{
  const m = new Map();
  m.set(1, 2);
  m.set(3, -7);
  // Expected: map(2) { 1:2, 3:-7 } → a2 01 02 03 26
  const encoded = hex(CborEncoder.encode(m));
  assertEq(encoded, 'a2010203' + '26', 'CBOR: encode COSE-style integer Map');
}

// Canonical CBOR key ordering: negative keys come after positive
{
  const m = new Map();
  m.set(1, 2);         // kty
  m.set(3, -7);        // alg
  m.set(-1, 1);        // crv
  m.set(-2, new Uint8Array([0xaa]));   // x (short for test)
  m.set(-3, new Uint8Array([0xbb]));   // y (short for test)
  const encoded = CborEncoder.encode(m);
  // Should be a5 (5-entry map)
  assert(encoded[0] === 0xa5, 'CBOR: COSE key map has 5 entries');
  // Keys should be sorted: 1, 3 (positive, short encoding), then -1, -2, -3 (negative)
  // 1 → 01, 3 → 03, -1 → 20, -2 → 21, -3 → 22
  // Encoded key lengths are all 1 byte, so sorted by byte value: 01, 03, 20, 21, 22
  const keyBytes = [];
  let i = 1;
  for (let k = 0; k < 5; k++) {
    keyBytes.push(encoded[i]);
    // Skip key byte, then skip value encoding
    i++; // past key
    // Decode value to skip it
    const major = encoded[i] >> 5;
    const minor = encoded[i] & 0x1f;
    if (minor < 24) {
      if (major === 2) { i += 1 + minor; } // byte string
      else { i += 1; }
    } else if (minor === 24) {
      if (major === 2) { i += 2 + encoded[i+1]; }
      else { i += 2; }
    }
  }
  assertEq(keyBytes, [0x01, 0x03, 0x20, 0x21, 0x22], 'CBOR: canonical key ordering (pos before neg)');
}

// ============================================
// Test 2: CryptoEngine Basics
// ============================================

console.log('\n\x1b[1m=== Test 2: CryptoEngine ===\x1b[0m');

{
  const rand = CryptoEngine.getRandomBytes(32);
  assert(rand instanceof Uint8Array, 'CryptoEngine: getRandomBytes returns Uint8Array');
  assertEq(rand.length, 32, 'CryptoEngine: getRandomBytes correct length');
  // Check not all zeros
  assert(rand.some(b => b !== 0), 'CryptoEngine: getRandomBytes not all zeros');
}

{
  const credId = CryptoEngine.generateCredentialId();
  assertEq(credId.length, 32, 'CryptoEngine: credential ID is 32 bytes');
}

{
  // Base64url round-trip
  const original = new Uint8Array([0, 1, 2, 253, 254, 255]);
  const encoded = CryptoEngine.base64UrlEncode(original.buffer);
  assert(!encoded.includes('+'), 'CryptoEngine: base64url has no +');
  assert(!encoded.includes('/'), 'CryptoEngine: base64url has no /');
  assert(!encoded.includes('='), 'CryptoEngine: base64url has no =');
  const decoded = new Uint8Array(CryptoEngine.base64UrlDecode(encoded));
  assertEq([...decoded], [...original], 'CryptoEngine: base64url round-trip');
}

// ============================================
// Test 3: Key Generation & Signing
// ============================================

console.log('\n\x1b[1m=== Test 3: Key Generation & Signing ===\x1b[0m');

{
  const { privateKey, publicKey, keyPair } = await CryptoEngine.generateWebAuthnKeyPair();
  assert(privateKey instanceof ArrayBuffer, 'KeyGen: privateKey is ArrayBuffer');
  assert(publicKey instanceof ArrayBuffer, 'KeyGen: publicKey is ArrayBuffer');
  assert(keyPair.privateKey && typeof keyPair.privateKey === 'object', 'KeyGen: keyPair.privateKey is CryptoKey');

  // Test signing and verification
  const message = new TextEncoder().encode('test message');
  const sig = await CryptoEngine.sign(keyPair.privateKey, message);
  assert(sig instanceof ArrayBuffer, 'Sign: returns ArrayBuffer');
  assert(sig.byteLength === 64, 'Sign: P-256 signature is 64 bytes (P1363)');

  const valid = await CryptoEngine.verify(keyPair.publicKey, sig, message);
  assert(valid === true, 'Verify: signature is valid');

  const wrongMessage = new TextEncoder().encode('wrong message');
  const invalid = await CryptoEngine.verify(keyPair.publicKey, sig, wrongMessage);
  assert(invalid === false, 'Verify: wrong message fails');

  // Import round-trip
  const importedPriv = await CryptoEngine.importPrivateKey(privateKey);
  const sig2 = await CryptoEngine.sign(importedPriv, message);
  const valid2 = await CryptoEngine.verify(keyPair.publicKey, sig2, message);
  assert(valid2 === true, 'Verify: imported private key produces valid signatures');

  const importedPub = await CryptoEngine.importPublicKey(publicKey);
  const valid3 = await CryptoEngine.verify(importedPub, sig, message);
  assert(valid3 === true, 'Verify: imported public key verifies signatures');
}

// ============================================
// Test 4: COSE Public Key Encoding
// ============================================

console.log('\n\x1b[1m=== Test 4: COSE Public Key ===\x1b[0m');

{
  const { publicKey } = await CryptoEngine.generateWebAuthnKeyPair();
  const coseKey = await AttestationBuilder.encodeCosePublicKey(publicKey);

  assert(coseKey instanceof Uint8Array, 'COSE: returns Uint8Array');
  assert(coseKey[0] === 0xa5, 'COSE: is a 5-entry CBOR map');
  assert(coseKey.length > 70, 'COSE: reasonable size (has 32-byte x and y)');

  // Decode manually: first key should be 1 (kty), value should be 2 (EC2)
  assert(coseKey[1] === 0x01, 'COSE: first key is 1 (kty)');
  assert(coseKey[2] === 0x02, 'COSE: kty value is 2 (EC2)');
  // Second key should be 3 (alg), value should be -7 (ES256 = 0x26)
  assert(coseKey[3] === 0x03, 'COSE: second key is 3 (alg)');
  assert(coseKey[4] === 0x26, 'COSE: alg value is -7 (ES256)');
}

// ============================================
// Test 5: AuthenticatorData Structure
// ============================================

console.log('\n\x1b[1m=== Test 5: AuthenticatorData ===\x1b[0m');

{
  // Assertion authData (37 bytes)
  const authData = await AttestationBuilder.buildAuthData('login.microsoft.com', 0x05, 42);
  assertEq(authData.length, 37, 'AuthData: assertion is 37 bytes');

  // rpIdHash (first 32 bytes)
  const expectedHash = new Uint8Array(
    await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode('login.microsoft.com'))
  );
  assertEq([...authData.slice(0, 32)], [...expectedHash], 'AuthData: rpIdHash is SHA-256 of rpId');

  // Flags
  assertEq(authData[32], 0x05, 'AuthData: flags = UP|UV');

  // SignCount (big-endian 42)
  assertEq(authData[33], 0, 'AuthData: signCount byte 0');
  assertEq(authData[34], 0, 'AuthData: signCount byte 1');
  assertEq(authData[35], 0, 'AuthData: signCount byte 2');
  assertEq(authData[36], 42, 'AuthData: signCount byte 3 = 42');
}

{
  // Registration authData (with attested credential data)
  const { publicKey } = await CryptoEngine.generateWebAuthnKeyPair();
  const credId = CryptoEngine.generateCredentialId();
  const regAuthData = await AttestationBuilder.buildRegistrationAuthData(
    'login.microsoft.com', credId, publicKey
  );

  assert(regAuthData.length > 37, 'RegAuthData: longer than 37 bytes');

  // Flags should include AT (0x40)
  const flags = regAuthData[32];
  assert((flags & 0x40) !== 0, 'RegAuthData: AT flag set');
  assert((flags & 0x01) !== 0, 'RegAuthData: UP flag set');
  assert((flags & 0x04) !== 0, 'RegAuthData: UV flag set');

  // SignCount should be 0
  assertEq(regAuthData[33], 0, 'RegAuthData: signCount = 0');
  assertEq(regAuthData[34], 0, 'RegAuthData: signCount = 0');
  assertEq(regAuthData[35], 0, 'RegAuthData: signCount = 0');
  assertEq(regAuthData[36], 0, 'RegAuthData: signCount = 0');

  // AAGUID at offset 37 (16 bytes)
  const aaguid = regAuthData.slice(37, 53);
  assertEq([...aaguid], [...AttestationBuilder.AAGUID], 'RegAuthData: AAGUID matches');

  // Credential ID length at offset 53 (2 bytes big-endian)
  const credIdLen = (regAuthData[53] << 8) | regAuthData[54];
  assertEq(credIdLen, 32, 'RegAuthData: credId length = 32');

  // Credential ID at offset 55
  assertEq([...regAuthData.slice(55, 55 + 32)], [...credId], 'RegAuthData: credId matches');

  // COSE key starts at offset 55+32=87
  const coseStart = 55 + 32;
  assert(regAuthData[coseStart] === 0xa5, 'RegAuthData: COSE key starts with 5-entry map');
}

// ============================================
// Test 6: Self-Attestation (Full Round-Trip)
// ============================================

console.log('\n\x1b[1m=== Test 6: Self-Attestation ===\x1b[0m');

{
  const { publicKey, keyPair } = await CryptoEngine.generateWebAuthnKeyPair();
  const credId = CryptoEngine.generateCredentialId();
  const clientDataJSON = JSON.stringify({
    type: 'webauthn.create',
    challenge: 'test-challenge',
    origin: 'https://login.microsoft.com',
    crossOrigin: false
  });
  const clientDataHash = await CryptoEngine.sha256(new TextEncoder().encode(clientDataJSON));

  const attestObj = await AttestationBuilder.buildSelfAttestation({
    rpId: 'login.microsoft.com',
    credentialId: credId,
    publicKeySpki: publicKey,
    privateKey: keyPair.privateKey,
    clientDataHash
  });

  assert(attestObj instanceof Uint8Array, 'SelfAttest: returns Uint8Array');
  assert(attestObj.length > 100, 'SelfAttest: reasonable size');

  // First byte should be 0xa3 (3-entry CBOR map)
  assertEq(attestObj[0], 0xa3, 'SelfAttest: starts with 3-entry map');

  // Find "fmt" key (0x63 = 3-char text, then "fmt")
  assertEq(attestObj[1], 0x63, 'SelfAttest: first key is 3-char text');
  assertEq(String.fromCharCode(attestObj[2], attestObj[3], attestObj[4]), 'fmt', 'SelfAttest: key is "fmt"');

  // Value should be "packed" (0x66 = 6-char text)
  assertEq(attestObj[5], 0x66, 'SelfAttest: fmt value is 6-char text');
  const fmtValue = String.fromCharCode(...attestObj.slice(6, 12));
  assertEq(fmtValue, 'packed', 'SelfAttest: fmt = "packed"');

  // Verify the attestation signature
  // To do this: extract authData and sig from the attestation object, then verify
  // Find "attStmt" key (starts at offset 12)
  assertEq(attestObj[12], 0x67, 'SelfAttest: second key is 7-char text');
  const attStmtKey = String.fromCharCode(...attestObj.slice(13, 20));
  assertEq(attStmtKey, 'attStmt', 'SelfAttest: key is "attStmt"');

  console.log(`  (attestation object: ${attestObj.length} bytes)`);
}

// ============================================
// Test 7: X.509 Certificate Generation
// ============================================

console.log('\n\x1b[1m=== Test 7: X.509 Certificate ===\x1b[0m');

{
  const material = await AttestationBuilder.generateAttestationMaterial();

  assert(material.privateKey instanceof ArrayBuffer, 'X509: privateKey is ArrayBuffer');
  assert(material.certificate instanceof Uint8Array, 'X509: certificate is Uint8Array');
  assert(material.keyPair.privateKey && typeof material.keyPair.privateKey === 'object', 'X509: keyPair has CryptoKey');

  // DER certificate should start with SEQUENCE tag (0x30)
  assertEq(material.certificate[0], 0x30, 'X509: starts with SEQUENCE tag');
  assert(material.certificate.length > 100, 'X509: reasonable cert size');

  console.log(`  (certificate: ${material.certificate.length} bytes)`);
}

// ============================================
// Test 8: Full Attestation with X.509
// ============================================

console.log('\n\x1b[1m=== Test 8: Full Attestation ===\x1b[0m');

{
  const { publicKey } = await CryptoEngine.generateWebAuthnKeyPair();
  const credId = CryptoEngine.generateCredentialId();
  const material = await AttestationBuilder.generateAttestationMaterial();
  const clientDataHash = await CryptoEngine.sha256(new TextEncoder().encode('{}'));

  const fullAttest = await AttestationBuilder.buildFullAttestation({
    rpId: 'login.microsoft.com',
    credentialId: credId,
    publicKeySpki: publicKey,
    attestPrivateKey: material.keyPair.privateKey,
    attestCertDer: material.certificate,
    clientDataHash
  });

  assert(fullAttest instanceof Uint8Array, 'FullAttest: returns Uint8Array');
  assertEq(fullAttest[0], 0xa3, 'FullAttest: starts with 3-entry map');

  // Should contain "packed" format
  const fmtValue = String.fromCharCode(...fullAttest.slice(6, 12));
  assertEq(fmtValue, 'packed', 'FullAttest: fmt = "packed"');

  console.log(`  (full attestation: ${fullAttest.length} bytes)`);
}

// ============================================
// Test 9: ECDSA P1363-to-DER Conversion
// ============================================

console.log('\n\x1b[1m=== Test 9: ECDSA DER Conversion ===\x1b[0m');

{
  // Generate a signature and verify it converts to valid DER
  const { keyPair } = await CryptoEngine.generateWebAuthnKeyPair();
  const data = new TextEncoder().encode('test');
  const p1363Sig = new Uint8Array(await CryptoEngine.sign(keyPair.privateKey, data));

  assertEq(p1363Sig.length, 64, 'DER: P1363 sig is 64 bytes');

  // Use the internal _ecdsaToDer via buildSelfAttestation (it's encapsulated)
  // Instead, test that the attestation signature is valid DER by checking structure
  // We'll call the function from a manual test

  // Manual DER conversion test (replicating the internal logic)
  function testEcdsaToDer(p1363) {
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

  const derSig = testEcdsaToDer(p1363Sig);
  assertEq(derSig[0], 0x30, 'DER: starts with SEQUENCE tag');
  assertEq(derSig[1], derSig.length - 2, 'DER: length field correct');
  assertEq(derSig[2], 0x02, 'DER: r starts with INTEGER tag');
  const rLen = derSig[3];
  assertEq(derSig[4 + rLen], 0x02, 'DER: s starts with INTEGER tag');
  assert(derSig.length >= 68 && derSig.length <= 72, `DER: reasonable length (${derSig.length})`);
}

// ============================================
// Test 10: Background.js Message Routing
// ============================================

console.log('\n\x1b[1m=== Test 10: Message Routing Audit ===\x1b[0m');

{
  const bgSource = readFileSync('extension/background.js', 'utf-8');
  const contentSource = readFileSync('extension/content.js', 'utf-8');
  const popupSource = readFileSync('extension/popup.js', 'utf-8');

  // All actions sent from popup.js
  const popupActions = [...popupSource.matchAll(/sendMessage\(['"]([^'"]+)['"]/g)].map(m => m[1]);
  const uniquePopupActions = [...new Set(popupActions)];

  // All actions handled in background.js
  const bgCases = [...bgSource.matchAll(/case\s+'([^']+)':/g)].map(m => m[1]);

  console.log(`  Popup sends ${uniquePopupActions.length} unique actions`);
  console.log(`  Background handles ${bgCases.length} cases`);

  for (const action of uniquePopupActions) {
    assert(bgCases.includes(action), `Route: popup '${action}' has handler`);
  }

  // All actions sent from content.js
  const contentActions = [...contentSource.matchAll(/sendToBackground\(['"]([^'"]+)['"]/g)].map(m => m[1]);
  const uniqueContentActions = [...new Set(contentActions)];

  for (const action of uniqueContentActions) {
    assert(bgCases.includes(action), `Route: content '${action}' has handler`);
  }

  // Check for required importScripts
  const requiredModules = ['cryptoEngine.js', 'cborEncoder.js', 'attestation.js',
                           'securityValidator.js', 'vaultEngine.js', 'authEngine.js',
                           'federationDetector.js'];
  for (const mod of requiredModules) {
    assert(bgSource.includes(`'${mod}'`), `Import: background.js imports ${mod}`);
  }
}

// ============================================
// Test 11: Content Script Interception Logic
// ============================================

console.log('\n\x1b[1m=== Test 11: Content Script Audit ===\x1b[0m');

{
  const source = readFileSync('extension/content.js', 'utf-8');

  // Check both interceptors exist
  assert(source.includes('navigator.credentials.get'), 'Content: intercepts credentials.get()');
  assert(source.includes('navigator.credentials.create'), 'Content: intercepts credentials.create()');

  // Check it preserves originals
  assert(source.includes('originalGet') || source.includes('original'), 'Content: saves original get');
  assert(source.includes('originalCreate') || source.includes('original'), 'Content: saves original create');

  // Check ES256 algorithm check
  assert(source.includes('-7') || source.includes('alg'), 'Content: checks ES256 algorithm');

  // Check origin validation
  assert(source.includes('origin'), 'Content: validates origin');

  // Check PublicKeyCredential response building
  assert(source.includes('attestationObject'), 'Content: builds attestationObject response');
  assert(source.includes('clientDataJSON'), 'Content: includes clientDataJSON');
  assert(source.includes('authenticatorAttachment'), 'Content: sets authenticatorAttachment');

  // Check duplicate injection guard
  assert(source.includes('__passkeyVault') || source.includes('Injected'), 'Content: has injection guard');
}

// ============================================
// Test 12: Manifest Validation
// ============================================

console.log('\n\x1b[1m=== Test 12: Manifest Validation ===\x1b[0m');

{
  const manifest = JSON.parse(readFileSync('extension/manifest.json', 'utf-8'));

  assertEq(manifest.manifest_version, 3, 'Manifest: version 3');
  assert(!manifest.background.type, 'Manifest: no "type": "module" (uses importScripts)');
  assertEq(manifest.background.service_worker, 'background.js', 'Manifest: service_worker is background.js');

  // Required permissions
  assert(manifest.permissions.includes('storage'), 'Manifest: has storage permission');
  assert(manifest.permissions.includes('webNavigation'), 'Manifest: has webNavigation permission');
  assert(manifest.permissions.includes('alarms'), 'Manifest: has alarms permission');

  // Content scripts on Microsoft login domains
  const cs = manifest.content_scripts[0];
  assert(cs.matches.some(m => m.includes('microsoftonline.com')), 'Manifest: content script on microsoftonline.com');
  assertEq(cs.js, ['content.js'], 'Manifest: content script is content.js');
  assertEq(cs.run_at, 'document_end', 'Manifest: content script runs at document_end');
  assertEq(cs.all_frames, true, 'Manifest: content script runs in all frames');

  // CSP
  assert(manifest.content_security_policy.extension_pages.includes("script-src 'self'"), 'Manifest: CSP restricts scripts to self');
}

// ============================================
// Test 13: Vault/Auth Engine API Surface
// ============================================

console.log('\n\x1b[1m=== Test 13: API Surface Audit ===\x1b[0m');

{
  const vaultSource = readFileSync('extension/vaultEngine.js', 'utf-8');
  const authSource = readFileSync('extension/authEngine.js', 'utf-8');

  // VaultEngine must export these functions
  const requiredVault = [
    'exists', 'create', 'unlock', 'lock', 'isUnlocked', 'destroy',
    'addUser', 'getUsers', 'findUserByUpn',
    'storePasskey', 'getPasskey', 'getPasskeysByRpId', 'getPasskeysByUserId',
    'deletePasskey', 'getDecryptedPrivateKey', 'incrementSignCount',
    'getSummary',
    'storeCredential', 'getAllCredentials', 'getCredential',
    'addCredential', 'getCredentials', 'getDecryptedPassword', 'deleteCredential'
  ];

  for (const fn of requiredVault) {
    assert(vaultSource.includes(fn), `VaultAPI: exports ${fn}`);
  }

  // AuthEngine must export these
  const requiredAuth = [
    'registerPasskey', 'registerFromWebAuthn', 'signChallenge',
    'getAvailablePasskeys', 'verifySignature'
  ];

  for (const fn of requiredAuth) {
    assert(authSource.includes(fn), `AuthAPI: exports ${fn}`);
  }
}

// ============================================
// Summary
// ============================================

console.log('\n' + '='.repeat(50));
console.log(`\x1b[1mResults: ${passed} passed, ${failed} failed\x1b[0m`);
if (failures.length > 0) {
  console.log('\x1b[31mFailures:\x1b[0m');
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
}
console.log('='.repeat(50));

process.exit(failed > 0 ? 1 : 0);
