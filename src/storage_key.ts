import { blake3 } from '@noble/hashes/blake3.js'
import { toHex } from './bytes.ts'

/**
 * The storage key of an encrypted file: the BLAKE3 hash of its ciphertext, in hex. It is computed
 * over the ciphertext, so the same file in two key scopes gets two unrelated keys.
 */
export function storageKey(encryptedFile: Uint8Array): string {
  return toHex(blake3(encryptedFile))
}
