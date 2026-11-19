import { concatBytes, uuidToBytes } from './bytes.ts'
import { encodeCbor } from './cbor.ts'
import { CryptoError } from './errors.ts'
import type { CryptoProvider } from './provider.ts'
import type { SymmetricKey } from './envelope.ts'

/**
 * The account key kept on a device between restarts, so that the device opens it with no
 * password and no connection. Each runtime keeps a wrapping key in its own safe place: a
 * non-extractable WebCrypto key in IndexedDB, the Keychain, the Android Keystore, Electron
 * `safeStorage`. The format of the entry is the same everywhere, and it is defined here.
 *
 * `sealed` = version (1) ‖ nonce (12) ‖ AES-256-GCM ciphertext of the account key ‖ tag (16).
 * The associated data binds the account, the account key ID and the expiry, so an entry cannot be
 * moved to another account or kept past its expiry by an edit.
 */

export const DEVICE_KEY_FORMAT_VERSION = 1
const DEVICE_KEY_LABEL = new TextEncoder().encode('tashfir-device-key-v1')
const NONCE_LENGTH = 12

/** One stored account key, as a holder keeps it. */
export interface DeviceKeyEntry {
  accountId: string
  accountKeyId: string
  /**
   * Milliseconds since the Unix epoch. After it, the entry is deleted unread. Null: the entry
   * stays until the account signs out on this device.
   */
  expiresAt: number | null
  sealed: Uint8Array
}

/** The wrapping key of a device. Its bytes may be impossible to read (WebCrypto, a keystore). */
export interface DeviceWrappingKey {
  seal(nonce: Uint8Array, plaintext: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>
  open(nonce: Uint8Array, sealed: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>
}

/**
 * Where a runtime keeps the wrapping key and the entries. One wrapping key for each device; one
 * entry for each account on it.
 */
export interface DeviceKeyHolder {
  /** The wrapping key of the device. The first call makes it. */
  wrappingKey(): Promise<DeviceWrappingKey>
  read(accountId: string): Promise<DeviceKeyEntry | null>
  write(entry: DeviceKeyEntry): Promise<void>
  delete(accountId: string): Promise<void>
  accountIds(): Promise<string[]>
}

/** A wrapping key whose bytes the runtime can read (a keystore that returns them, or tests). */
export function rawDeviceWrappingKey(provider: CryptoProvider, bytes: Uint8Array): DeviceWrappingKey {
  return {
    seal: (nonce, plaintext, associatedData) =>
      provider.aes256GcmSeal(bytes, nonce, plaintext, associatedData),
    open: (nonce, sealed, associatedData) =>
      provider.aes256GcmOpen(bytes, nonce, sealed, associatedData),
  }
}

/** The associated data of an entry: the label, then deterministic CBOR with integer keys. */
export function deviceKeyAssociatedData(
  entry: Pick<DeviceKeyEntry, 'accountId' | 'accountKeyId' | 'expiresAt'>
): Uint8Array {
  return concatBytes(
    DEVICE_KEY_LABEL,
    encodeCbor(
      new Map<number, unknown>([
        [0, DEVICE_KEY_FORMAT_VERSION],
        [1, uuidToBytes(entry.accountId)],
        [2, uuidToBytes(entry.accountKeyId)],
        [3, entry.expiresAt],
      ])
    )
  )
}

/** Seals an entry with a chosen nonce. Only the test vectors choose it (`/testing`). */
export async function sealDeviceKeyEntryWith(
  wrappingKey: DeviceWrappingKey,
  input: { accountId: string; accountKey: SymmetricKey; expiresAt: number | null },
  nonce: Uint8Array
): Promise<DeviceKeyEntry> {
  const fields = {
    accountId: input.accountId,
    accountKeyId: input.accountKey.id,
    expiresAt: input.expiresAt,
  }
  const ciphertext = await wrappingKey.seal(
    nonce,
    input.accountKey.bytes,
    deviceKeyAssociatedData(fields)
  )
  return {
    ...fields,
    sealed: concatBytes(new Uint8Array([DEVICE_KEY_FORMAT_VERSION]), nonce, ciphertext),
  }
}

/** Opens an entry. Throws `E_DECRYPT_FAILED` when it does not open with this wrapping key. */
export async function openDeviceKeyEntry(
  wrappingKey: DeviceWrappingKey,
  entry: DeviceKeyEntry
): Promise<SymmetricKey> {
  if (entry.sealed[0] !== DEVICE_KEY_FORMAT_VERSION) {
    throw new CryptoError('E_UNKNOWN_VERSION', 'unknown device key format version')
  }
  const nonce = entry.sealed.subarray(1, 1 + NONCE_LENGTH)
  const ciphertext = entry.sealed.subarray(1 + NONCE_LENGTH)
  try {
    const bytes = await wrappingKey.open(nonce, ciphertext, deviceKeyAssociatedData(entry))
    return { id: entry.accountKeyId, bytes }
  } catch {
    throw new CryptoError('E_DECRYPT_FAILED', 'the device key entry does not open')
  }
}

/** Keeps the account key of an account on this device, in place of an earlier one. */
export async function keepAccountKeyOnDevice(
  provider: CryptoProvider,
  holder: DeviceKeyHolder,
  input: {
    accountId: string
    accountKey: SymmetricKey
    /** Omit it for an entry with no expiry. */
    lifetimeMs?: number
    now?: number
  }
): Promise<void> {
  const entry = await sealDeviceKeyEntryWith(
    await holder.wrappingKey(),
    {
      accountId: input.accountId,
      accountKey: input.accountKey,
      expiresAt:
        input.lifetimeMs === undefined ? null : (input.now ?? Date.now()) + input.lifetimeMs,
    },
    provider.randomBytes(NONCE_LENGTH)
  )
  await holder.write(entry)
}

/**
 * The account key that this device keeps for an account, or null. An expired entry, or one that
 * does not open (a new wrapping key, an edit), is deleted.
 */
export async function openAccountKeyOnDevice(
  holder: DeviceKeyHolder,
  accountId: string,
  options: { now?: number } = {}
): Promise<SymmetricKey | null> {
  const entry = await holder.read(accountId)
  if (!entry) return null
  const expired = entry.expiresAt !== null && entry.expiresAt <= (options.now ?? Date.now())
  if (entry.accountId !== accountId || expired) {
    await holder.delete(accountId)
    return null
  }
  try {
    return await openDeviceKeyEntry(await holder.wrappingKey(), entry)
  } catch (error) {
    if (!(error instanceof CryptoError)) throw error
    await holder.delete(accountId)
    return null
  }
}

/** Deletes the account key that this device keeps for an account. */
export async function forgetAccountKeyOnDevice(
  holder: DeviceKeyHolder,
  accountId: string
): Promise<void> {
  await holder.delete(accountId)
}

/** Deletes the account keys of all other accounts on this device. */
export async function keepOnlyAccountOnDevice(
  holder: DeviceKeyHolder,
  accountId: string
): Promise<void> {
  const accountIds = await holder.accountIds()
  await Promise.all(
    accountIds.filter((storedId) => storedId !== accountId).map((storedId) => holder.delete(storedId))
  )
}
