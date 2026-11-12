import {
  bytesToUuid,
  concatBytes,
  expectLength,
  uint16,
  utf8,
  uuidToBytes,
  newKeyId,
} from './bytes.ts'
import { encodeContext, encodeParts } from './context.ts'
import { SYMMETRIC_KEY_LENGTH, TAG_LENGTH, type SymmetricKey } from './envelope.ts'
import { CryptoError } from './errors.ts'
import { hkdfExpand, hkdfExtract } from './hkdf.ts'
import { pad, unpad } from './padding.ts'
import {
  X_WING_CIPHERTEXT_LENGTH,
  X_WING_PUBLIC_KEY_LENGTH,
  X_WING_SECRET_KEY_LENGTH,
  type CryptoProvider,
} from './provider.ts'
import { currentSuite, ENVELOPE_VERSION, suiteForReading } from './suites.ts'

const MODE_BASE = 0x00
const VERSION_LABEL = utf8('HPKE-v1')

export interface HpkeSuiteIds {
  kemId: number
  kdfId: number
  aeadId: number
}

export interface HpkeContext {
  key: Uint8Array
  baseNonce: Uint8Array
  exporterSecret: Uint8Array
}

function hpkeSuiteId(ids: HpkeSuiteIds): Uint8Array {
  return concatBytes(utf8('HPKE'), uint16(ids.kemId), uint16(ids.kdfId), uint16(ids.aeadId))
}

async function labeledExtract(
  provider: CryptoProvider,
  suiteId: Uint8Array,
  salt: Uint8Array,
  label: string,
  inputKeyMaterial: Uint8Array
): Promise<Uint8Array> {
  return hkdfExtract(
    provider,
    salt,
    concatBytes(VERSION_LABEL, suiteId, utf8(label), inputKeyMaterial)
  )
}

async function labeledExpand(
  provider: CryptoProvider,
  suiteId: Uint8Array,
  pseudorandomKey: Uint8Array,
  label: string,
  info: Uint8Array,
  length: number
): Promise<Uint8Array> {
  return hkdfExpand(
    provider,
    pseudorandomKey,
    concatBytes(uint16(length), VERSION_LABEL, suiteId, utf8(label), info),
    length
  )
}

/**
 * The key schedule of RFC 9180 §5.1 in base mode (no PSK), for a KDF with a 32-byte hash.
 * `keyLength` is Nk of the AEAD. The KEM shared secret goes in as it is.
 */
export async function hpkeKeySchedule(
  provider: CryptoProvider,
  ids: HpkeSuiteIds,
  sharedSecret: Uint8Array,
  info: Uint8Array,
  keyLength: number,
  nonceLength = 12
): Promise<HpkeContext> {
  if (ids.kdfId !== 0x0001) throw new CryptoError('E_UNSUPPORTED', 'Only HKDF-SHA-256 is supported')
  const suiteId = hpkeSuiteId(ids)
  const empty = new Uint8Array(0)
  const pskIdHash = await labeledExtract(provider, suiteId, empty, 'psk_id_hash', empty)
  const infoHash = await labeledExtract(provider, suiteId, empty, 'info_hash', info)
  const keyScheduleContext = concatBytes(Uint8Array.of(MODE_BASE), pskIdHash, infoHash)
  const secret = await labeledExtract(provider, suiteId, sharedSecret, 'secret', empty)
  return {
    key: await labeledExpand(provider, suiteId, secret, 'key', keyScheduleContext, keyLength),
    baseNonce: await labeledExpand(
      provider,
      suiteId,
      secret,
      'base_nonce',
      keyScheduleContext,
      nonceLength
    ),
    exporterSecret: await labeledExpand(provider, suiteId, secret, 'exp', keyScheduleContext, 32),
  }
}

/** An X-Wing key pair, with the UUID of its key version. */
export interface KemKeyPair {
  id: string
  publicKey: Uint8Array
  /** The 32-byte seed. */
  secretKey: Uint8Array
}

export async function generateKemKeyPair(provider: CryptoProvider): Promise<KemKeyPair> {
  const secretKey = provider.randomBytes(X_WING_SECRET_KEY_LENGTH)
  return {
    id: newKeyId(provider.randomBytes(16)),
    publicKey: await provider.xWingPublicKey(secretKey),
    secretKey,
  }
}

/** version (1) ‖ suite ID (1) ‖ recipient key UUID (16), then the encapsulated key (1120). */
export const PUBLIC_KEY_WRAP_HEADER_LENGTH = 18

export interface PublicKeyWrapHeader {
  version: number
  suiteId: number
  recipientKeyId: string
}

export function readPublicKeyWrapHeader(wrap: Uint8Array): PublicKeyWrapHeader {
  if (wrap.length < PUBLIC_KEY_WRAP_HEADER_LENGTH + X_WING_CIPHERTEXT_LENGTH + TAG_LENGTH) {
    throw new CryptoError('E_MALFORMED', 'The public-key wrap is too short')
  }
  if (wrap[0] !== ENVELOPE_VERSION) {
    throw new CryptoError('E_UNKNOWN_VERSION', `Unknown envelope version ${wrap[0]}`)
  }
  return { version: wrap[0], suiteId: wrap[1], recipientKeyId: bytesToUuid(wrap.subarray(2, 18)) }
}

/** The HPKE `info`: the purpose and the UUID of the recipient key (one key pair version). */
function wrapInfo(recipientKeyId: string): Uint8Array {
  return encodeParts([utf8('key-wrap'), uuidToBytes(recipientKeyId)])
}

/**
 * The wrap with its randomness as an argument. Only the known-answer tests pass
 * `randomness` (the 64-byte X-Wing `eseed`).
 */
export async function wrapKeyToPublicKeyWith(
  provider: CryptoProvider,
  recipient: { id: string; publicKey: Uint8Array },
  key: SymmetricKey,
  options: { randomness?: Uint8Array } = {}
): Promise<Uint8Array> {
  expectLength(recipient.publicKey, X_WING_PUBLIC_KEY_LENGTH, 'An X-Wing public key')
  expectLength(key.bytes, SYMMETRIC_KEY_LENGTH, 'A symmetric key')
  const suite = currentSuite()
  const header = concatBytes(Uint8Array.of(ENVELOPE_VERSION, suite.id), uuidToBytes(recipient.id))
  const { ciphertext: encapsulatedKey, sharedSecret } = await provider.xWingEncapsulate(
    recipient.publicKey,
    options.randomness
  )
  const context = await hpkeKeySchedule(
    provider,
    suite.hpke,
    sharedSecret,
    wrapInfo(recipient.id),
    32
  )
  // One message for each HPKE context, so the nonce is the base nonce (sequence number 0).
  const sealed = await provider.aes256GcmSeal(
    context.key,
    context.baseNonce,
    pad(key.bytes),
    concatBytes(header, encodeContext({ purpose: 'key-wrap', wrappedKeyId: key.id }))
  )
  return concatBytes(header, encapsulatedKey, sealed)
}

/**
 * Wraps a symmetric key to an X-Wing public key with HPKE base mode. 1187 bytes.
 */
export async function wrapKeyToPublicKey(
  provider: CryptoProvider,
  recipient: { id: string; publicKey: Uint8Array },
  key: SymmetricKey
): Promise<Uint8Array> {
  return wrapKeyToPublicKeyWith(provider, recipient, key)
}

export async function unwrapKeyWithSecretKey(
  provider: CryptoProvider,
  recipient: { id: string; secretKey: Uint8Array },
  wrap: Uint8Array,
  wrappedKeyId: string
): Promise<SymmetricKey> {
  const header = readPublicKeyWrapHeader(wrap)
  const suite = suiteForReading(header.suiteId)
  if (header.recipientKeyId !== recipient.id) {
    throw new CryptoError('E_KEY_MISMATCH', `The wrap is for key ${header.recipientKeyId}`)
  }
  expectLength(recipient.secretKey, X_WING_SECRET_KEY_LENGTH, 'An X-Wing secret key')
  const encapsulatedKeyEnd = PUBLIC_KEY_WRAP_HEADER_LENGTH + X_WING_CIPHERTEXT_LENGTH
  let bytes: Uint8Array
  try {
    const sharedSecret = await provider.xWingDecapsulate(
      wrap.subarray(PUBLIC_KEY_WRAP_HEADER_LENGTH, encapsulatedKeyEnd),
      recipient.secretKey
    )
    const context = await hpkeKeySchedule(
      provider,
      suite.hpke,
      sharedSecret,
      wrapInfo(recipient.id),
      32
    )
    bytes = unpad(
      await provider.aes256GcmOpen(
        context.key,
        context.baseNonce,
        wrap.subarray(encapsulatedKeyEnd),
        concatBytes(
          wrap.subarray(0, PUBLIC_KEY_WRAP_HEADER_LENGTH),
          encodeContext({ purpose: 'key-wrap', wrappedKeyId })
        )
      )
    )
  } catch (error) {
    throw new CryptoError('E_DECRYPT_FAILED', 'The wrap does not open with this key pair', {
      cause: error,
    })
  }
  expectLength(bytes, SYMMETRIC_KEY_LENGTH, 'A wrapped key')
  return { id: wrappedKeyId, bytes }
}
