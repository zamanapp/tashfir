import { decode, encode, rfc8949EncodeOptions } from 'cborg'
import { equalBytes } from './bytes.ts'
import { CryptoError } from './errors.ts'

/** Deterministic CBOR (RFC 8949 §4.2.1): the same value always gives the same bytes. */
export function encodeCbor(value: unknown): Uint8Array {
  return encode(value, rfc8949EncodeOptions)
}

/**
 * Accepts only deterministic CBOR. A second encoding of one value would let two parties sign or
 * hash different bytes for the same blob, so a non-canonical input is rejected. `useMaps` decodes
 * maps into `Map`, for maps with integer keys.
 */
export function decodeCbor<Value = unknown>(
  bytes: Uint8Array,
  options: { useMaps?: boolean } = {}
): Value {
  let value: Value
  try {
    value = decode(bytes, {
      strict: true,
      rejectDuplicateMapKeys: true,
      useMaps: options.useMaps ?? false,
    }) as Value
  } catch (error) {
    throw new CryptoError('E_MALFORMED', 'The blob is not valid CBOR', { cause: error })
  }
  if (!equalBytes(encodeCbor(value), bytes)) {
    throw new CryptoError('E_MALFORMED', 'The blob is not deterministic CBOR')
  }
  return value
}
