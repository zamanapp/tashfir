import { base32crockford } from '@scure/base'
import { entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39'
import { wordlist as english } from '@scure/bip39/wordlists/english.js'
import { concatBytes, equalBytes, newKeyId, utf8 } from './bytes.ts'
import { openBytes, readEnvelopeHeader, sealBytes, unwrapKey, wrapKey, type SymmetricKey } from './envelope.ts'
import { CryptoError } from './errors.ts'
import { hkdf } from './hkdf.ts'
import type { CryptoProvider } from './provider.ts'

/**
 * The recovery key of an account (encryption PRD §4.4): 32 random bytes, so that it stays strong
 * against Grover's algorithm while its wrap waits on the server. It has two written forms of the
 * same bytes, and a QR payload:
 *
 * - 24 English BIP-39 words. The last word carries an 8-bit checksum.
 * - A code in Crockford base32: the key and a 3-byte SHA-256 checksum, 56 characters in 14
 *   groups of 4. Base32 has no case and no look-alike letters, so it is easier to copy by hand.
 * - The QR payload `zaman-recovery:1:<code without dashes>`. It holds no address.
 */
export const RECOVERY_KEY_LENGTH = 32
const CODE_CHECKSUM_LENGTH = 3
const CODE_GROUP = 4
const QR_PREFIX = 'zaman-recovery:1:'
const PROOF_INFO = utf8('tashfir-recovery-auth-v1')
const UNLOCK_INFO = utf8('tashfir-recovery-unlock-v1')

function expectRecoveryKey(recoveryKey: Uint8Array): void {
  if (recoveryKey.length !== RECOVERY_KEY_LENGTH) {
    throw new CryptoError('E_INVALID_INPUT', `A recovery key has ${RECOVERY_KEY_LENGTH} bytes`)
  }
}

export function generateRecoveryKey(provider: CryptoProvider): Uint8Array {
  return provider.randomBytes(RECOVERY_KEY_LENGTH)
}

/** The 24 words, in order. */
export function recoveryKeyToWords(recoveryKey: Uint8Array): string[] {
  expectRecoveryKey(recoveryKey)
  return entropyToMnemonic(recoveryKey, english).split(' ')
}

/**
 * Reads the 24 words, in any case and with any spaces between them. Throws `E_INVALID_INPUT`
 * for a word that is not on the list, a wrong count, or a wrong checksum (a typing error).
 */
export function recoveryKeyFromWords(words: string | string[]): Uint8Array {
  const phrase = (Array.isArray(words) ? words.join(' ') : words).trim().toLowerCase().split(/\s+/).join(' ')
  let entropy: Uint8Array
  try {
    entropy = mnemonicToEntropy(phrase, english)
  } catch (error) {
    throw new CryptoError('E_INVALID_INPUT', 'These words are not a recovery key', { cause: error })
  }
  expectRecoveryKey(entropy)
  return entropy
}

async function codeChecksum(provider: CryptoProvider, recoveryKey: Uint8Array): Promise<Uint8Array> {
  return (await provider.sha256(recoveryKey)).subarray(0, CODE_CHECKSUM_LENGTH)
}

/** The 56 characters of the code, without dashes. */
async function codeCharacters(provider: CryptoProvider, recoveryKey: Uint8Array): Promise<string> {
  expectRecoveryKey(recoveryKey)
  return base32crockford.encode(concatBytes(recoveryKey, await codeChecksum(provider, recoveryKey)))
}

/** The code, in groups of 4 joined by dashes: `XXXX-XXXX-…`. */
export async function recoveryKeyToCode(provider: CryptoProvider, recoveryKey: Uint8Array): Promise<string> {
  const characters = await codeCharacters(provider, recoveryKey)
  return characters.match(new RegExp(`.{1,${CODE_GROUP}}`, 'g'))!.join('-')
}

/**
 * Reads a code, in any case, with or without dashes and spaces. Crockford base32 reads I and L as
 * 1, and O as 0. Throws `E_INVALID_INPUT` for a wrong length or a wrong checksum.
 */
export async function recoveryKeyFromCode(provider: CryptoProvider, code: string): Promise<Uint8Array> {
  const characters = code.replace(/[\s-]/g, '').toUpperCase().replace(/[IL]/g, '1').replace(/O/g, '0')
  let bytes: Uint8Array
  try {
    bytes = base32crockford.decode(characters)
  } catch (error) {
    throw new CryptoError('E_INVALID_INPUT', 'This code is not a recovery key', { cause: error })
  }
  if (bytes.length !== RECOVERY_KEY_LENGTH + CODE_CHECKSUM_LENGTH) {
    throw new CryptoError('E_INVALID_INPUT', 'This code is not a recovery key')
  }
  const recoveryKey = bytes.subarray(0, RECOVERY_KEY_LENGTH)
  if (!equalBytes(bytes.subarray(RECOVERY_KEY_LENGTH), await codeChecksum(provider, recoveryKey))) {
    throw new CryptoError('E_INVALID_INPUT', 'This code has a typing error')
  }
  return Uint8Array.from(recoveryKey)
}

/** The text of the QR code. */
export async function recoveryQrPayload(provider: CryptoProvider, recoveryKey: Uint8Array): Promise<string> {
  return QR_PREFIX + (await codeCharacters(provider, recoveryKey))
}

export async function recoveryKeyFromQrPayload(provider: CryptoProvider, payload: string): Promise<Uint8Array> {
  if (!payload.startsWith(QR_PREFIX)) {
    throw new CryptoError('E_INVALID_INPUT', 'This QR code is not a Zaman recovery key')
  }
  return recoveryKeyFromCode(provider, payload.slice(QR_PREFIX.length))
}

/**
 * The proof that a person has the recovery key: `HKDF(recovery key, "auth")`. The client sends
 * it to the server, which stores only a hash of it. It cannot open the account key.
 */
export async function recoveryProof(provider: CryptoProvider, recoveryKey: Uint8Array): Promise<Uint8Array> {
  expectRecoveryKey(recoveryKey)
  return hkdf(provider, new Uint8Array(0), recoveryKey, PROOF_INFO, 32)
}

/** The key of the recovery unlock wrap. Exported for the known-answer vectors. */
export async function recoveryUnlockKey(provider: CryptoProvider, recoveryKey: Uint8Array, id: string): Promise<SymmetricKey> {
  expectRecoveryKey(recoveryKey)
  return { id, bytes: await hkdf(provider, new Uint8Array(0), recoveryKey, UNLOCK_INFO, 32) }
}

/** What the server stores for a recovery key. The key itself never leaves the device. */
export interface RecoveryKit {
  recoveryKey: Uint8Array
  /** The account key wrapped by a key from the recovery key. */
  unlockWrap: Uint8Array
  /** The recovery key sealed by the account key, so that a signed-in device can show it again. */
  copy: Uint8Array
  proof: Uint8Array
}

/**
 * Makes a recovery key for an account key (or a new one that replaces it): the recovery unlock
 * wrap, the copy under the account key, and the proof.
 */
export async function createRecoveryKit(provider: CryptoProvider, accountKey: SymmetricKey): Promise<RecoveryKit> {
  const recoveryKey = generateRecoveryKey(provider)
  const unlockKey = await recoveryUnlockKey(provider, recoveryKey, newKeyId(provider.randomBytes(16)))
  return {
    recoveryKey,
    unlockWrap: await wrapKey(provider, unlockKey, accountKey),
    copy: await sealBytes(provider, accountKey, recoveryKey, { purpose: 'key-wrap', wrappedKeyId: unlockKey.id }),
    proof: await recoveryProof(provider, recoveryKey),
  }
}

/** Opens the account key with the recovery key (recovery, case A). */
export async function openAccountKeyWithRecoveryKey(
  provider: CryptoProvider,
  recoveryKey: Uint8Array,
  unlockWrap: Uint8Array,
  accountKeyVersionId: string
): Promise<SymmetricKey> {
  const { keyId } = readEnvelopeHeader(unlockWrap)
  return unwrapKey(provider, await recoveryUnlockKey(provider, recoveryKey, keyId), unlockWrap, accountKeyVersionId)
}

/** Opens the copy of the recovery key, to show it again. `unlockWrap` names the key of the copy. */
export async function openRecoveryKeyCopy(
  provider: CryptoProvider,
  accountKey: SymmetricKey,
  copy: Uint8Array,
  unlockWrap: Uint8Array
): Promise<Uint8Array> {
  const { keyId } = readEnvelopeHeader(unlockWrap)
  const recoveryKey = await openBytes(provider, accountKey, copy, { purpose: 'key-wrap', wrappedKeyId: keyId })
  expectRecoveryKey(recoveryKey)
  return recoveryKey
}
