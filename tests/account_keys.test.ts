import { describe, expect, test } from 'vitest'
import {
  createAccountKeys,
  openAccountKeyWithPassword,
  openSecretKey,
  wrapAccountKeyForPassword,
} from '../src/account_keys.ts'
import { equalBytes } from '../src/bytes.ts'
import { emptyRegistryChain, appendRegistryEntry, decodeRegistryEntry } from '../src/registry.ts'
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
})
