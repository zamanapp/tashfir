import { concatBytes } from './bytes.ts'
import { CryptoError } from './errors.ts'
import type { CryptoProvider } from './provider.ts'

const HASH_LENGTH = 32

/**
 * HKDF-SHA-256 (RFC 5869) over the HMAC of the provider. HPKE needs Extract and Expand as two
 * steps, and WebCrypto and Node only give the one-shot form.
 */
export async function hkdfExtract(
  provider: CryptoProvider,
  salt: Uint8Array,
  inputKeyMaterial: Uint8Array
): Promise<Uint8Array> {
  return provider.hmacSha256(salt.length > 0 ? salt : new Uint8Array(HASH_LENGTH), inputKeyMaterial)
}

export async function hkdfExpand(
  provider: CryptoProvider,
  pseudorandomKey: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  if (!Number.isInteger(length) || length < 1 || length > 255 * HASH_LENGTH) {
    throw new CryptoError('E_INVALID_INPUT', `HKDF cannot produce ${length} bytes`)
  }
  const output = new Uint8Array(length)
  let previous: Uint8Array = new Uint8Array(0)
  for (let counter = 1, offset = 0; offset < length; counter++) {
    previous = await provider.hmacSha256(
      pseudorandomKey,
      concatBytes(previous, info, Uint8Array.of(counter))
    )
    output.set(previous.subarray(0, Math.min(HASH_LENGTH, length - offset)), offset)
    offset += HASH_LENGTH
  }
  return output
}

export async function hkdf(
  provider: CryptoProvider,
  salt: Uint8Array,
  inputKeyMaterial: Uint8Array,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  return hkdfExpand(provider, await hkdfExtract(provider, salt, inputKeyMaterial), info, length)
}
