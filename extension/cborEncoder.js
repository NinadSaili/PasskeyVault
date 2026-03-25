/**
 * CborEncoder - Minimal CBOR (RFC 8949) encoder for WebAuthn attestation objects.
 *
 * Supports: unsigned/negative integers, byte strings, text strings,
 * arrays, maps (string-keyed objects and integer-keyed Maps), null, boolean.
 * Canonical CBOR sorting for Map keys (required by COSE/WebAuthn).
 */
const CborEncoder = (() => {
  'use strict';

  /**
   * Encode a JavaScript value as CBOR bytes.
   * @param {*} value - Value to encode.
   * @returns {Uint8Array} CBOR-encoded bytes.
   */
  function encode(value) {
    if (value === null || value === undefined) {
      return new Uint8Array([0xf6]); // CBOR null
    }
    if (typeof value === 'boolean') {
      return new Uint8Array([value ? 0xf5 : 0xf4]);
    }
    if (typeof value === 'number' && Number.isInteger(value)) {
      return value >= 0
        ? _encodeHead(0, value)              // Major type 0: unsigned int
        : _encodeHead(1, -1 - value);        // Major type 1: negative int
    }
    if (typeof value === 'string') {
      const bytes = new TextEncoder().encode(value);
      return _concat(_encodeHead(3, bytes.length), bytes);
    }
    if (value instanceof Uint8Array) {
      return _concat(_encodeHead(2, value.length), value);
    }
    if (value instanceof ArrayBuffer) {
      const bytes = new Uint8Array(value);
      return _concat(_encodeHead(2, bytes.length), bytes);
    }
    if (Array.isArray(value)) {
      return _concatAll([
        _encodeHead(4, value.length),
        ...value.map(encode)
      ]);
    }
    if (value instanceof Map) {
      return _encodeMap(value);
    }
    if (typeof value === 'object') {
      return _encodePlainObject(value);
    }
    throw new Error('CborEncoder: unsupported type ' + typeof value);
  }

  /**
   * Encode a Map with canonical CBOR key ordering.
   * Used for COSE keys (integer-keyed maps).
   */
  function _encodeMap(map) {
    const entries = [...map.entries()];
    // Canonical CBOR: sort by encoded key length first, then byte comparison
    entries.sort((a, b) => {
      const ka = encode(a[0]);
      const kb = encode(b[0]);
      if (ka.length !== kb.length) return ka.length - kb.length;
      for (let i = 0; i < ka.length; i++) {
        if (ka[i] !== kb[i]) return ka[i] - kb[i];
      }
      return 0;
    });

    return _concatAll([
      _encodeHead(5, entries.length),
      ...entries.flatMap(([k, v]) => [encode(k), encode(v)])
    ]);
  }

  /**
   * Encode a plain JS object as a CBOR map with string keys.
   * Keys are sorted lexicographically by their UTF-8 encoding.
   */
  function _encodePlainObject(obj) {
    const keys = Object.keys(obj).sort();
    return _concatAll([
      _encodeHead(5, keys.length),
      ...keys.flatMap(k => [encode(k), encode(obj[k])])
    ]);
  }

  /**
   * Encode a CBOR head (major type + argument).
   */
  function _encodeHead(majorType, n) {
    const mt = majorType << 5;
    if (n < 24) return new Uint8Array([mt | n]);
    if (n < 0x100) return new Uint8Array([mt | 24, n]);
    if (n < 0x10000) return new Uint8Array([mt | 25, (n >> 8) & 0xff, n & 0xff]);
    if (n < 0x100000000) {
      return new Uint8Array([
        mt | 26,
        (n >> 24) & 0xff, (n >> 16) & 0xff,
        (n >> 8) & 0xff, n & 0xff
      ]);
    }
    throw new Error('CborEncoder: value too large');
  }

  function _concat(a, b) {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
  }

  function _concatAll(arrays) {
    let totalLen = 0;
    for (const arr of arrays) totalLen += arr.length;
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }

  return Object.freeze({ encode });
})();

if (typeof globalThis !== 'undefined') {
  globalThis.CborEncoder = CborEncoder;
}
