import { newKeyId, utf8 } from './bytes.ts'
import { generateSymmetricKey, openBytes, readEnvelopeHeader, sealBytes, unwrapKey, wrapKey, type SymmetricKey } from './envelope.ts'
import { generateKemKeyPair, type KemKeyPair } from './hpke.ts'
import { hkdf } from './hkdf.ts'
import type { CryptoProvider } from './provider.ts'
import {
  encodeRegistryEntry,
  registryEntryHash,
  REGISTRY_FORMAT_VERSION,
  signRegistryEntry,
  type RegistryEntry,
  type RegistryKeyPurpose,
  type SignedRegistryEntry,
} from './registry.ts'
import { generateSigningKeyPair, type SigningKeyPair } from './signature.ts'

/** The HKDF label that turns the OPAQUE export key into the key of the password unlock wrap. */
const PASSWORD_UNLOCK_INFO = utf8('tashfir-password-unlock-v1')

/** A key pair of an account, with the UUID that its registry entry and its row use. */
export interface AccountKeyPair {
  id: string
  purpose: RegistryKeyPurpose
  publicKey: Uint8Array
  secretKey: Uint8Array
}

/** What the server stores for the keys of a new account. It holds no key in the clear. */
export interface AccountKeyBundle {
  /** The first version of the account key: its UUID only. The key never leaves the device. */
  accountKeyVersion: { id: string; version: number }
  /** The two key pairs: each public key, and the secret key wrapped by the account key. */
  keyPairs: {
    id: string
    purpose: RegistryKeyPurpose
    version: number
    publicKey: Uint8Array
    wrappedSecretKey: Uint8Array
  }[]
  /** The account key wrapped by a key from the OPAQUE export key. */
  passwordUnlockWrap: Uint8Array
  /** The first two entries of the registry chain: the signing key, then the encryption key. */
  registryEntries: SignedRegistryEntry[]
}

export interface AccountKeys {
  accountKey: SymmetricKey
  signingKeyPair: AccountKeyPair
  encryptionKeyPair: AccountKeyPair
  bundle: AccountKeyBundle
}

/**
 * The key of the password unlock wrap: HKDF-SHA-256 of the OPAQUE export key (encryption PRD
 * §4.2). A new password gives a new export key, so a change of password makes this wrap again and
 * nothing else. `id` is the UUID that the envelope names.
 */
export async function passwordUnlockKey(
  provider: CryptoProvider,
  exportKey: Uint8Array,
  id: string
): Promise<SymmetricKey> {
  return { id, bytes: await hkdf(provider, new Uint8Array(0), exportKey, PASSWORD_UNLOCK_INFO, 32) }
}

/** Wraps the account key under a key from the export key. Also used after a change of password. */
export async function wrapAccountKeyForPassword(
  provider: CryptoProvider,
  exportKey: Uint8Array,
  accountKey: SymmetricKey
): Promise<Uint8Array> {
  const unlockKey = await passwordUnlockKey(provider, exportKey, newKeyId(provider.randomBytes(16)))
  return wrapKey(provider, unlockKey, accountKey)
}

/**
 * Opens the account key after a login. The UUID of the unlock key is in the header of the wrap,
 * so the export key is enough. Throws `E_DECRYPT_FAILED` for the export key of another password.
 */
export async function openAccountKeyWithPassword(
  provider: CryptoProvider,
  exportKey: Uint8Array,
  passwordUnlockWrap: Uint8Array,
  accountKeyVersionId: string
): Promise<SymmetricKey> {
  const { keyId } = readEnvelopeHeader(passwordUnlockWrap)
  const unlockKey = await passwordUnlockKey(provider, exportKey, keyId)
  return unwrapKey(provider, unlockKey, passwordUnlockWrap, accountKeyVersionId)
}

/** Wraps the secret key of a key pair under the account key. The pair's UUID is in the context. */
export async function wrapSecretKey(
  provider: CryptoProvider,
  accountKey: SymmetricKey,
  pair: { id: string; secretKey: Uint8Array }
): Promise<Uint8Array> {
  return sealBytes(provider, accountKey, pair.secretKey, { purpose: 'key-wrap', wrappedKeyId: pair.id })
}

export async function openSecretKey(
  provider: CryptoProvider,
  accountKey: SymmetricKey,
  pairId: string,
  wrappedSecretKey: Uint8Array
): Promise<Uint8Array> {
  return openBytes(provider, accountKey, wrappedSecretKey, { purpose: 'key-wrap', wrappedKeyId: pairId })
}

/**
 * Makes the keys of a new account on the device (encryption PRD §4.1): the account key, the
 * signing key pair and the encryption key pair, the password unlock wrap from the OPAQUE export
 * key, and the first two registry entries. The signing key signs both entries; the first entry
 * signs itself.
 *
 * `accountId` is the account UUID that the server chose at the start of the registration.
 */
export async function createAccountKeys(
  provider: CryptoProvider,
  { accountId, exportKey }: { accountId: string; exportKey: Uint8Array }
): Promise<AccountKeys> {
  const accountKey = generateSymmetricKey(provider)
  const signing: SigningKeyPair = await generateSigningKeyPair(provider)
  const signingKeyPair: AccountKeyPair = {
    id: newKeyId(provider.randomBytes(16)),
    purpose: 'signing',
    publicKey: signing.publicKey,
    secretKey: signing.secretKey,
  }
  const kem: KemKeyPair = await generateKemKeyPair(provider)
  const encryptionKeyPair: AccountKeyPair = {
    id: kem.id,
    purpose: 'encryption',
    publicKey: kem.publicKey,
    secretKey: kem.secretKey,
  }

  const first: RegistryEntry = {
    formatVersion: REGISTRY_FORMAT_VERSION,
    accountId,
    sequence: 0,
    previousHash: null,
    kind: 'publish',
    keyId: signingKeyPair.id,
    purpose: 'signing',
    algorithm: 'mldsa65-ed25519',
    publicKey: signingKeyPair.publicKey,
    revocationReason: null,
    signerKeyId: signingKeyPair.id,
  }
  const firstBytes = encodeRegistryEntry(first)
  const second: RegistryEntry = {
    ...first,
    sequence: 1,
    previousHash: await registryEntryHash(provider, firstBytes),
    keyId: encryptionKeyPair.id,
    purpose: 'encryption',
    algorithm: 'xwing-draft-11',
    publicKey: encryptionKeyPair.publicKey,
  }
  const secondBytes = encodeRegistryEntry(second)

  const bundle: AccountKeyBundle = {
    accountKeyVersion: { id: accountKey.id, version: 1 },
    keyPairs: await Promise.all(
      [signingKeyPair, encryptionKeyPair].map(async (pair) => ({
        id: pair.id,
        purpose: pair.purpose,
        version: 1,
        publicKey: pair.publicKey,
        wrappedSecretKey: await wrapSecretKey(provider, accountKey, pair),
      }))
    ),
    passwordUnlockWrap: await wrapAccountKeyForPassword(provider, exportKey, accountKey),
    registryEntries: [
      { entryBytes: firstBytes, signature: await signRegistryEntry(provider, signingKeyPair.secretKey, firstBytes) },
      { entryBytes: secondBytes, signature: await signRegistryEntry(provider, signingKeyPair.secretKey, secondBytes) },
    ],
  }
  return { accountKey, signingKeyPair, encryptionKeyPair, bundle }
}
