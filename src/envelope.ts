import { bytesToUuid, concatBytes, expectLength, newKeyId, uuidToBytes } from './bytes.ts'
import { decodeCbor, encodeCbor } from './cbor.ts'
import { encodeContext, type EnvelopeContext } from './context.ts'
import { CryptoError } from './errors.ts'
import { pad, unpad } from './padding.ts'
import type { CryptoProvider } from './provider.ts'
import { currentSuite, ENVELOPE_VERSION, suiteForReading } from './suites.ts'

export const SYMMETRIC_KEY_LENGTH = 32
export const NONCE_LENGTH = 12
export const TAG_LENGTH = 16
/** version (1) ‖ suite ID (1) ‖ key UUID (16) ‖ nonce (12) */
export const HEADER_LENGTH = 30

/** A symmetric key and the UUID of its key row. The version is on the row, not here. */
export interface SymmetricKey {
  id: string
  bytes: Uint8Array
}

export interface EnvelopeHeader {
  version: number
  suiteId: number
  keyId: string
  nonce: Uint8Array
}

export function generateSymmetricKey(provider: CryptoProvider): SymmetricKey {
  return {
    id: newKeyId(provider.randomBytes(16)),
    bytes: provider.randomBytes(SYMMETRIC_KEY_LENGTH),
  }
}

/** Reads the header without a key, so that a reader can find the key that opens the envelope. */
export function readEnvelopeHeader(envelope: Uint8Array): EnvelopeHeader {
  if (envelope.length < HEADER_LENGTH + TAG_LENGTH) {
    throw new CryptoError('E_MALFORMED', 'The envelope is too short')
  }
  const version = envelope[0]
  if (version !== ENVELOPE_VERSION) {
    throw new CryptoError('E_UNKNOWN_VERSION', `Unknown envelope version ${version}`)
  }
  return {
    version,
    suiteId: envelope[1],
    keyId: bytesToUuid(envelope.subarray(2, 18)),
    nonce: envelope.subarray(18, HEADER_LENGTH),
  }
}

/**
 * The seal with its randomness as arguments. Only the known-answer tests pass a nonce
 * (`@zamanapp/tashfir/testing`); `sealBytes` always takes a fresh random nonce.
 */
export async function sealBytesWith(
  provider: CryptoProvider,
  key: SymmetricKey,
  plaintext: Uint8Array,
  context: EnvelopeContext,
  options: { nonce?: Uint8Array; paddingZeroCount?: number } = {}
): Promise<Uint8Array> {
  expectLength(key.bytes, SYMMETRIC_KEY_LENGTH, 'A symmetric key')
  const nonce = options.nonce ?? provider.randomBytes(NONCE_LENGTH)
  expectLength(nonce, NONCE_LENGTH, 'The nonce')
  const header = concatBytes(
    Uint8Array.of(ENVELOPE_VERSION, currentSuite().id),
    uuidToBytes(key.id),
    nonce
  )
  const sealed = await provider.aes256GcmSeal(
    key.bytes,
    nonce,
    pad(plaintext, options.paddingZeroCount),
    concatBytes(header, encodeContext(context))
  )
  return concatBytes(header, sealed)
}

/**
 * Encrypts bytes under a symmetric key. One key seals at most 2^32 envelopes (random 96-bit
 * nonces); a key per item keeps every key far below this limit.
 */
export async function sealBytes(
  provider: CryptoProvider,
  key: SymmetricKey,
  plaintext: Uint8Array,
  context: EnvelopeContext
): Promise<Uint8Array> {
  return sealBytesWith(provider, key, plaintext, context)
}

export async function openBytes(
  provider: CryptoProvider,
  key: SymmetricKey,
  envelope: Uint8Array,
  context: EnvelopeContext
): Promise<Uint8Array> {
  const header = readEnvelopeHeader(envelope)
  suiteForReading(header.suiteId)
  if (header.keyId !== key.id) {
    throw new CryptoError('E_KEY_MISMATCH', `The envelope is sealed with key ${header.keyId}`)
  }
  expectLength(key.bytes, SYMMETRIC_KEY_LENGTH, 'A symmetric key')
  let padded: Uint8Array
  try {
    padded = await provider.aes256GcmOpen(
      key.bytes,
      header.nonce,
      envelope.subarray(HEADER_LENGTH),
      concatBytes(envelope.subarray(0, HEADER_LENGTH), encodeContext(context))
    )
  } catch (error) {
    throw new CryptoError(
      'E_DECRYPT_FAILED',
      'The envelope does not open with this key and context',
      {
        cause: error,
      }
    )
  }
  return unpad(padded)
}

/** Encrypts a blob: a value of one or more fields, as deterministic CBOR. */
export async function sealValue(
  provider: CryptoProvider,
  key: SymmetricKey,
  value: unknown,
  context: EnvelopeContext & { purpose: 'field' }
): Promise<Uint8Array> {
  return sealBytes(provider, key, encodeCbor(value), context)
}

/** The caller validates the result against the schema of its blob type. */
export async function openValue<Value = unknown>(
  provider: CryptoProvider,
  key: SymmetricKey,
  envelope: Uint8Array,
  context: EnvelopeContext & { purpose: 'field' }
): Promise<Value> {
  return decodeCbor<Value>(await openBytes(provider, key, envelope, context))
}

/**
 * Wraps a key under another symmetric key (an item key under a container key, a key version
 * under the next version). The associated data binds the UUIDs of both keys. About 80 bytes.
 */
export async function wrapKey(
  provider: CryptoProvider,
  wrappingKey: SymmetricKey,
  key: SymmetricKey
): Promise<Uint8Array> {
  expectLength(key.bytes, SYMMETRIC_KEY_LENGTH, 'A symmetric key')
  return sealBytes(provider, wrappingKey, key.bytes, { purpose: 'key-wrap', wrappedKeyId: key.id })
}

export async function unwrapKey(
  provider: CryptoProvider,
  wrappingKey: SymmetricKey,
  wrap: Uint8Array,
  wrappedKeyId: string
): Promise<SymmetricKey> {
  const bytes = await openBytes(provider, wrappingKey, wrap, { purpose: 'key-wrap', wrappedKeyId })
  expectLength(bytes, SYMMETRIC_KEY_LENGTH, 'A wrapped key')
  return { id: wrappedKeyId, bytes }
}
