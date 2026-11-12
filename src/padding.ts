import { CryptoError } from './errors.ts'

const PADDING_MARKER = 0x80

/**
 * ISO/IEC 7816-4 padding: the plaintext, then 0x80, then `zeroCount` zero bytes. Version 1 of the
 * envelope writes no zero bytes; padding to size buckets later changes only `zeroCount`.
 */
export function pad(plaintext: Uint8Array, zeroCount = 0): Uint8Array {
  if (!Number.isInteger(zeroCount) || zeroCount < 0) {
    throw new CryptoError('E_INVALID_INPUT', 'The padding length must be a positive integer')
  }
  const padded = new Uint8Array(plaintext.length + 1 + zeroCount)
  padded.set(plaintext)
  padded[plaintext.length] = PADDING_MARKER
  return padded
}

/** Readers strip any amount of padding, so a later writer can pad to buckets. */
export function unpad(padded: Uint8Array): Uint8Array {
  let index = padded.length - 1
  while (index >= 0 && padded[index] === 0) index--
  if (index < 0 || padded[index] !== PADDING_MARKER) {
    throw new CryptoError('E_MALFORMED', 'The plaintext has no valid padding')
  }
  return padded.subarray(0, index)
}
