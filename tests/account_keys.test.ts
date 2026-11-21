import { describe, expect, test } from 'vitest'
import {
  createAccountKeys,
  createResetKeys,
  openAccountKeyWithPassword,
  openSecretKey,
  wrapAccountKeyForPassword,
} from '../src/account_keys.ts'
import { equalBytes } from '../src/bytes.ts'
import {
  emptyRegistryChain,
  appendRegistryEntry,
  decodeRegistryEntry,
  publicKeyLengthOf,
  type RegistryChain,
} from '../src/registry.ts'
import { SIGNING_PUBLIC_KEY_LENGTH } from '../src/signature.ts'
import { X_WING_PUBLIC_KEY_LENGTH } from '../src/provider.ts'
import { signingPublicKey } from '../src/signature.ts'
import { fixedBytes } from './fixtures.ts'
import { providers } from './providers.ts'

const accountId = '0192f7a0-0000-7000-8000-0000000000c1'

async function errorCodeOf(action: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await action()
  } catch (error) {
    return (error as { code?: string }).code
  }
  return undefined
}

describe.each(providers)('account keys ($name)', (provider) => {
  test('the keys of a new account open with the export key and form a valid chain', async () => {
    const exportKey = fixedBytes(64, 0x41)
    const keys = await createAccountKeys(provider, { accountId, exportKey })
    const { bundle } = keys

    const opened = await openAccountKeyWithPassword(provider, exportKey, bundle.passwordUnlockWrap, bundle.accountKeyVersion.id)
    expect(equalBytes(opened.bytes, keys.accountKey.bytes)).toBe(true)

    for (const pair of bundle.keyPairs) {
      const secretKey = await openSecretKey(provider, opened, pair.id, pair.wrappedSecretKey)
      const own = pair.purpose === 'signing' ? keys.signingKeyPair : keys.encryptionKeyPair
      expect(equalBytes(secretKey, own.secretKey)).toBe(true)
    }
    expect(equalBytes(await signingPublicKey(provider, keys.signingKeyPair.secretKey), keys.signingKeyPair.publicKey)).toBe(true)

    let chain = emptyRegistryChain(accountId)
    for (const entry of bundle.registryEntries) chain = (await appendRegistryEntry(provider, chain, entry)).chain
    const [first, second] = bundle.registryEntries.map((entry) => decodeRegistryEntry(entry.entryBytes))
    expect(first.purpose).toBe('signing')
    expect(first.keyId).toBe(keys.signingKeyPair.id)
    expect(second.purpose).toBe('encryption')
    expect(second.keyId).toBe(keys.encryptionKeyPair.id)
    expect(equalBytes(second.publicKey!, keys.encryptionKeyPair.publicKey)).toBe(true)
  })

  test('another password cannot open the account key', async () => {
    const keys = await createAccountKeys(provider, { accountId, exportKey: fixedBytes(64, 0x41) })
    const code = await errorCodeOf(() =>
      openAccountKeyWithPassword(provider, fixedBytes(64, 0x42), keys.bundle.passwordUnlockWrap, keys.bundle.accountKeyVersion.id)
    )
    expect(code).toBe('E_DECRYPT_FAILED')
  })

  test('a new password wraps the same account key again', async () => {
    const keys = await createAccountKeys(provider, { accountId, exportKey: fixedBytes(64, 0x41) })
    const newExportKey = fixedBytes(64, 0x51)
    const wrap = await wrapAccountKeyForPassword(provider, newExportKey, keys.accountKey)
    const opened = await openAccountKeyWithPassword(provider, newExportKey, wrap, keys.accountKey.id)
    expect(equalBytes(opened.bytes, keys.accountKey.bytes)).toBe(true)
  })

  async function chainOf(entries: { entryBytes: Uint8Array; signature: Uint8Array }[], start?: RegistryChain) {
    let chain = start ?? emptyRegistryChain(accountId)
    for (const entry of entries) chain = (await appendRegistryEntry(provider, chain, entry)).chain
    return chain
  }

  test('the keys of a reset go on from the chain, open with the new password and revoke the old keys', async () => {
    const first = await createAccountKeys(provider, { accountId, exportKey: fixedBytes(64, 0x41) })
    const before = await chainOf(first.bundle.registryEntries)

    const exportKey = fixedBytes(64, 0x61)
    const reset = await createResetKeys(provider, {
      accountId,
      exportKey,
      chainHead: { nextSequence: before.nextSequence, previousHash: before.headHash! },
      version: 2,
    })
    const { bundle } = reset
    expect(bundle.accountKeyVersion.version).toBe(2)
    expect(bundle.keyPairs.map((pair) => pair.version)).toEqual([2, 2])
    expect(bundle.accountKeyVersion.id).not.toBe(first.bundle.accountKeyVersion.id)

    const opened = await openAccountKeyWithPassword(provider, exportKey, bundle.passwordUnlockWrap, bundle.accountKeyVersion.id)
    expect(equalBytes(opened.bytes, reset.accountKey.bytes)).toBe(true)
    for (const pair of bundle.keyPairs) {
      const secretKey = await openSecretKey(provider, opened, pair.id, pair.wrappedSecretKey)
      const own = pair.purpose === 'signing' ? reset.signingKeyPair : reset.encryptionKeyPair
      expect(equalBytes(secretKey, own.secretKey)).toBe(true)
    }

    const after = await chainOf(bundle.registryEntries, before)
    const [resetEntry, publishEntry] = bundle.registryEntries.map((entry) => decodeRegistryEntry(entry.entryBytes))
    expect(resetEntry.kind).toBe('reset')
    expect(resetEntry.sequence).toBe(2)
    expect(resetEntry.signerKeyId).toBe(reset.signingKeyPair.id)
    expect(publishEntry.kind).toBe('publish')
    expect(publishEntry.keyId).toBe(reset.encryptionKeyPair.id)
    expect(after.keys.get(first.signingKeyPair.id)?.revocation?.reason).toBe('reset')
    expect(after.keys.get(first.encryptionKeyPair.id)?.revocation?.reason).toBe('reset')
    expect(after.keys.get(reset.signingKeyPair.id)?.revocation).toBeNull()
    expect(after.keys.get(reset.encryptionKeyPair.id)?.revocation).toBeNull()
  })

  test('the keys of a reset do not fit a chain that moved on', async () => {
    const first = await createAccountKeys(provider, { accountId, exportKey: fixedBytes(64, 0x41) })
    const before = await chainOf(first.bundle.registryEntries)
    const reset = await createResetKeys(provider, {
      accountId,
      exportKey: fixedBytes(64, 0x61),
      chainHead: { nextSequence: before.nextSequence + 1, previousHash: before.headHash! },
      version: 2,
    })
    const code = await errorCodeOf(() => chainOf(reset.bundle.registryEntries, before))
    expect(code).toBe('E_REGISTRY_REJECTED')
  })

  test('a reset makes version 2 or later of the account key', async () => {
    const code = await errorCodeOf(() =>
      createResetKeys(provider, {
        accountId,
        exportKey: fixedBytes(64, 0x61),
        chainHead: { nextSequence: 2, previousHash: fixedBytes(32, 0x01) },
        version: 1,
      })
    )
    expect(code).toBe('E_INVALID_INPUT')
  })
})

describe('public key lengths', () => {
  test('each purpose has the length of its algorithm in suite 0x01', () => {
    expect(publicKeyLengthOf('signing')).toBe(SIGNING_PUBLIC_KEY_LENGTH)
    expect(publicKeyLengthOf('signing')).toBe(1984)
    expect(publicKeyLengthOf('encryption')).toBe(X_WING_PUBLIC_KEY_LENGTH)
    expect(publicKeyLengthOf('encryption')).toBe(1216)
  })
})
