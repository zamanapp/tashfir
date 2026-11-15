import { bytesToUuid, concatBytes, equalBytes, utf8, uuidToBytes } from './bytes.ts'
import { decodeCbor, encodeCbor } from './cbor.ts'
import { CryptoError } from './errors.ts'
import { X_WING_PUBLIC_KEY_LENGTH, type CryptoProvider } from './provider.ts'
import { sign, signWith, verify, SIGNING_PUBLIC_KEY_LENGTH } from './signature.ts'
import {
  KEM_ALGORITHMS,
  SIGNATURE_ALGORITHMS,
  type KemAlgorithm,
  type SignatureAlgorithm,
} from './suites.ts'

/**
 * The public key registry: for each account, an append-only chain of signed entries that
 * publish or revoke its public keys. The server and every client check an entry with the same
 * rules (`appendRegistryEntry`), so they agree on the keys of an account.
 *
 * An entry is deterministic CBOR, a map with integer keys. Key 0 is the format version, so it
 * is the first field of the bytes, and the same entry always gives the same bytes. The bytes can
 * become a leaf of a transparency log with no change.
 */
export const REGISTRY_FORMAT_VERSION = 1

/** The signature context of an entry: a signature of another kind never verifies as an entry. */
const SIGNATURE_CONTEXT = utf8('tashfir-registry-entry-v1')
/** The domain label of the entry hash. */
const HASH_LABEL = utf8('tashfir-registry-entry-hash-v1')
export const REGISTRY_HASH_LENGTH = 32

export type RegistryEntryKind = 'publish' | 'revoke' | 'reset'
export type RegistryKeyPurpose = 'signing' | 'encryption'
export type RevocationReason = 'lost_device' | 'reset' | 'superseded'

/**
 * - `publish`: adds a public key. The first entry of a chain publishes the signing key and signs
 *   itself. A later signing key is signed by an active signing key (the old one), so contacts
 *   see a key change, not an unknown key.
 * - `revoke`: ends a key, with a reason. A client does not wrap to a revoked key.
 * - `reset`: an account reset with no old key to sign with. It publishes a new signing key that
 *   signs itself and revokes every earlier key. Clients show it as a reset, never as a rotation.
 */
export interface RegistryEntry {
  formatVersion: number
  accountId: string
  sequence: number
  /** The hash of the previous entry of the account. Null only for sequence 0. */
  previousHash: Uint8Array | null
  kind: RegistryEntryKind
  keyId: string
  purpose: RegistryKeyPurpose
  /** Set for `publish` and `reset`. */
  algorithm: SignatureAlgorithm | KemAlgorithm | null
  /** Set for `publish` and `reset`. */
  publicKey: Uint8Array | null
  /** Set for `revoke`. */
  revocationReason: RevocationReason | null
  /** The signing key that signs the entry. */
  signerKeyId: string
}

const FIELD = {
  formatVersion: 0,
  accountId: 1,
  sequence: 2,
  previousHash: 3,
  kind: 4,
  keyId: 5,
  purpose: 6,
  algorithm: 7,
  publicKey: 8,
  revocationReason: 9,
  signerKeyId: 10,
} as const

const KINDS: readonly RegistryEntryKind[] = ['publish', 'revoke', 'reset']
const PURPOSES: readonly RegistryKeyPurpose[] = ['signing', 'encryption']
const REASONS: readonly RevocationReason[] = ['lost_device', 'reset', 'superseded']

/** The algorithm and the public key length that each purpose allows. */
const PURPOSE_KEYS: Record<
  RegistryKeyPurpose,
  { algorithms: readonly string[]; publicKeyLength: number }
> = {
  signing: {
    algorithms: Object.keys(SIGNATURE_ALGORITHMS),
    publicKeyLength: SIGNING_PUBLIC_KEY_LENGTH,
  },
  encryption: {
    algorithms: Object.keys(KEM_ALGORITHMS),
    publicKeyLength: X_WING_PUBLIC_KEY_LENGTH,
  },
}

function rejected(message: string): CryptoError {
  return new CryptoError('E_REGISTRY_REJECTED', message)
}

/** Checks the fields that do not depend on the chain. */
function checkEntryShape(entry: RegistryEntry): void {
  if (entry.formatVersion !== REGISTRY_FORMAT_VERSION) {
    throw new CryptoError('E_UNKNOWN_VERSION', `Unknown registry format ${entry.formatVersion}`)
  }
  if (!Number.isSafeInteger(entry.sequence) || entry.sequence < 0) {
    throw rejected('The sequence must be a whole number, 0 or more')
  }
  if ((entry.sequence === 0) !== (entry.previousHash === null)) {
    throw rejected('Only the first entry has no previous hash')
  }
  if (entry.previousHash && entry.previousHash.length !== REGISTRY_HASH_LENGTH) {
    throw rejected(`The previous hash must have ${REGISTRY_HASH_LENGTH} bytes`)
  }
  if (!KINDS.includes(entry.kind)) throw rejected(`Unknown entry kind`)
  if (!PURPOSES.includes(entry.purpose)) throw rejected(`Unknown key purpose`)

  const carriesKey = entry.kind === 'publish' || entry.kind === 'reset'
  if (carriesKey) {
    if (!entry.algorithm || !entry.publicKey || entry.revocationReason !== null) {
      throw rejected(`A ${entry.kind} entry has an algorithm and a public key, and no reason`)
    }
    const allowed = PURPOSE_KEYS[entry.purpose]
    if (!allowed.algorithms.includes(entry.algorithm)) {
      throw rejected(`The algorithm ${entry.algorithm} is not allowed for an ${entry.purpose} key`)
    }
    if (entry.publicKey.length !== allowed.publicKeyLength) {
      throw rejected(`An ${entry.purpose} public key must have ${allowed.publicKeyLength} bytes`)
    }
  } else {
    if (entry.algorithm !== null || entry.publicKey !== null || !entry.revocationReason) {
      throw rejected('A revoke entry has a reason, and no algorithm or public key')
    }
    if (!REASONS.includes(entry.revocationReason)) throw rejected('Unknown revocation reason')
  }
  if (entry.kind === 'reset' && entry.purpose !== 'signing') {
    throw rejected('A reset publishes a signing key')
  }
}

export function encodeRegistryEntry(entry: RegistryEntry): Uint8Array {
  checkEntryShape(entry)
  const fields = new Map<number, unknown>([
    [FIELD.formatVersion, entry.formatVersion],
    [FIELD.accountId, uuidToBytes(entry.accountId)],
    [FIELD.sequence, entry.sequence],
    [FIELD.kind, entry.kind],
    [FIELD.keyId, uuidToBytes(entry.keyId)],
    [FIELD.purpose, entry.purpose],
    [FIELD.signerKeyId, uuidToBytes(entry.signerKeyId)],
  ])
  // Absent fields are left out, not encoded as null: one value has one encoding.
  if (entry.previousHash) fields.set(FIELD.previousHash, entry.previousHash)
  if (entry.algorithm) fields.set(FIELD.algorithm, entry.algorithm)
  if (entry.publicKey) fields.set(FIELD.publicKey, entry.publicKey)
  if (entry.revocationReason) fields.set(FIELD.revocationReason, entry.revocationReason)
  return encodeCbor(fields)
}

export function decodeRegistryEntry(bytes: Uint8Array): RegistryEntry {
  const fields = decodeCbor<unknown>(bytes, { useMaps: true })
  if (!(fields instanceof Map)) throw new CryptoError('E_MALFORMED', 'An entry is a CBOR map')
  const known = new Set<unknown>(Object.values(FIELD))
  for (const fieldKey of fields.keys()) {
    if (!known.has(fieldKey)) throw new CryptoError('E_MALFORMED', 'An entry has an unknown field')
  }

  const read = <Value>(
    field: number,
    expected: 'number' | 'string' | 'bytes',
    optional = false
  ): Value | null => {
    const value: unknown = fields.get(field)
    if (value === undefined) {
      if (optional) return null
      throw new CryptoError('E_MALFORMED', `An entry has no field ${field}`)
    }
    const matches =
      expected === 'bytes' ? value instanceof Uint8Array : typeof value === expected
    if (!matches) throw new CryptoError('E_MALFORMED', `Field ${field} of an entry is not ${expected}`)
    return value as Value
  }

  const formatVersion = read<number>(FIELD.formatVersion, 'number')!
  if (formatVersion !== REGISTRY_FORMAT_VERSION) {
    throw new CryptoError('E_UNKNOWN_VERSION', `Unknown registry format ${formatVersion}`)
  }
  const entry: RegistryEntry = {
    formatVersion,
    accountId: bytesToUuid(read<Uint8Array>(FIELD.accountId, 'bytes')!),
    sequence: read<number>(FIELD.sequence, 'number')!,
    previousHash: read<Uint8Array>(FIELD.previousHash, 'bytes', true),
    kind: read<RegistryEntryKind>(FIELD.kind, 'string')!,
    keyId: bytesToUuid(read<Uint8Array>(FIELD.keyId, 'bytes')!),
    purpose: read<RegistryKeyPurpose>(FIELD.purpose, 'string')!,
    algorithm: read<SignatureAlgorithm | KemAlgorithm>(FIELD.algorithm, 'string', true),
    publicKey: read<Uint8Array>(FIELD.publicKey, 'bytes', true),
    revocationReason: read<RevocationReason>(FIELD.revocationReason, 'string', true),
    signerKeyId: bytesToUuid(read<Uint8Array>(FIELD.signerKeyId, 'bytes')!),
  }
  checkEntryShape(entry)
  return entry
}

/** SHA-256(label ‖ entry bytes). The next entry of the account holds it as `previousHash`. */
export async function registryEntryHash(
  provider: CryptoProvider,
  entryBytes: Uint8Array
): Promise<Uint8Array> {
  return provider.sha256(concatBytes(HASH_LABEL, entryBytes))
}

export async function signRegistryEntry(
  provider: CryptoProvider,
  signingSecretKey: Uint8Array,
  entryBytes: Uint8Array
): Promise<Uint8Array> {
  return sign(provider, signingSecretKey, entryBytes, SIGNATURE_CONTEXT)
}

/** The signature with fixed ML-DSA randomness. Only the known-answer vectors use it. */
export async function signRegistryEntryWith(
  provider: CryptoProvider,
  signingSecretKey: Uint8Array,
  entryBytes: Uint8Array,
  options: { randomness?: Uint8Array }
): Promise<Uint8Array> {
  return signWith(provider, signingSecretKey, entryBytes, SIGNATURE_CONTEXT, options)
}

export async function verifyRegistryEntrySignature(
  provider: CryptoProvider,
  signingPublicKey: Uint8Array,
  entryBytes: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  return verify(provider, signingPublicKey, entryBytes, signature, SIGNATURE_CONTEXT)
}

export interface RegistryKey {
  keyId: string
  purpose: RegistryKeyPurpose
  algorithm: SignatureAlgorithm | KemAlgorithm
  publicKey: Uint8Array
  /** The sequence of the entry that published the key. */
  publishedAt: number
  /** Null while the key is active. */
  revocation: { reason: RevocationReason; sequence: number } | null
}

/** What a chain says after its last entry. */
export interface RegistryChain {
  accountId: string
  nextSequence: number
  /** The hash of the last entry. Null for an empty chain. */
  headHash: Uint8Array | null
  keys: ReadonlyMap<string, RegistryKey>
}

export function emptyRegistryChain(accountId: string): RegistryChain {
  uuidToBytes(accountId)
  return { accountId, nextSequence: 0, headHash: null, keys: new Map() }
}

export interface SignedRegistryEntry {
  entryBytes: Uint8Array
  signature: Uint8Array
}

function activeSigningKey(chain: RegistryChain, keyId: string): RegistryKey {
  const key = chain.keys.get(keyId)
  if (!key || key.purpose !== 'signing' || key.revocation) {
    throw rejected('The signer is not an active signing key of the account')
  }
  return key
}

/**
 * Checks an entry against the chain and returns the chain with the entry. The chain given is
 * not changed. Throws `E_REGISTRY_REJECTED` when the entry breaks a rule, `E_MALFORMED` when its
 * bytes are not an entry.
 */
export async function appendRegistryEntry(
  provider: CryptoProvider,
  chain: RegistryChain,
  signed: SignedRegistryEntry
): Promise<{ chain: RegistryChain; entry: RegistryEntry; entryHash: Uint8Array }> {
  const entry = decodeRegistryEntry(signed.entryBytes)
  if (entry.accountId !== chain.accountId) throw rejected('The entry is for another account')
  if (entry.sequence !== chain.nextSequence) {
    throw rejected(`The next sequence of the account is ${chain.nextSequence}`)
  }
  if (
    chain.headHash &&
    (!entry.previousHash || !equalBytes(entry.previousHash, chain.headHash))
  ) {
    throw rejected('The previous hash is not the hash of the last entry')
  }

  const keys = new Map(chain.keys)
  let signerPublicKey: Uint8Array

  if (entry.kind === 'revoke') {
    const revoked = keys.get(entry.keyId)
    if (!revoked || revoked.purpose !== entry.purpose) throw rejected('No such key to revoke')
    if (revoked.revocation) throw rejected('The key is revoked already')
    if (entry.signerKeyId === entry.keyId) throw rejected('A key cannot revoke itself')
    signerPublicKey = activeSigningKey(chain, entry.signerKeyId).publicKey
    keys.set(entry.keyId, {
      ...revoked,
      revocation: { reason: entry.revocationReason!, sequence: entry.sequence },
    })
  } else {
    if (keys.has(entry.keyId)) throw rejected('The key ID is in the chain already')
    const selfSigned = entry.signerKeyId === entry.keyId
    if (entry.kind === 'reset') {
      if (entry.sequence === 0) throw rejected('A chain starts with a publish entry')
      if (!selfSigned) throw rejected('A reset entry signs itself')
      // A reset ends every earlier key: the old keys may be in the hands of someone else.
      for (const [keyId, key] of keys) {
        if (!key.revocation) {
          keys.set(keyId, { ...key, revocation: { reason: 'reset', sequence: entry.sequence } })
        }
      }
      signerPublicKey = entry.publicKey!
    } else if (entry.sequence === 0) {
      if (entry.purpose !== 'signing' || !selfSigned) {
        throw rejected('The first entry publishes the signing key and signs itself')
      }
      signerPublicKey = entry.publicKey!
    } else {
      if (selfSigned) throw rejected('Only the first entry and a reset sign themselves')
      signerPublicKey = activeSigningKey(chain, entry.signerKeyId).publicKey
    }
    keys.set(entry.keyId, {
      keyId: entry.keyId,
      purpose: entry.purpose,
      algorithm: entry.algorithm!,
      publicKey: entry.publicKey!,
      publishedAt: entry.sequence,
      revocation: null,
    })
  }

  if (
    !(await verifyRegistryEntrySignature(
      provider,
      signerPublicKey,
      signed.entryBytes,
      signed.signature
    ))
  ) {
    throw rejected('The signature of the entry is not valid')
  }

  const entryHash = await registryEntryHash(provider, signed.entryBytes)
  return {
    chain: { accountId: chain.accountId, nextSequence: entry.sequence + 1, headHash: entryHash, keys },
    entry,
    entryHash,
  }
}

/** Checks a whole chain from its first entry. */
export async function replayRegistryChain(
  provider: CryptoProvider,
  accountId: string,
  entries: readonly SignedRegistryEntry[]
): Promise<RegistryChain> {
  let chain = emptyRegistryChain(accountId)
  for (const signed of entries) {
    chain = (await appendRegistryEntry(provider, chain, signed)).chain
  }
  return chain
}
