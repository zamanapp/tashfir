import { describe, expect, test } from 'vitest'
import { equalBytes } from '../src/bytes.ts'
import {
  forgetAccountKeyOnDevice,
  keepAccountKeyOnDevice,
  keepOnlyAccountOnDevice,
  openAccountKeyOnDevice,
  rawDeviceWrappingKey,
  type DeviceKeyEntry,
  type DeviceKeyHolder,
} from '../src/device_keys.ts'
import { IndexedDbDeviceKeyHolder } from '../src/device_holders/indexed_db.ts'
import { fixedBytes } from './fixtures.ts'
import { providers } from './providers.ts'

const accountId = '0192f7a0-0000-7000-8000-000000000001'
const otherAccountId = '0192f7a0-0000-7000-8000-000000000002'
const accountKey = { id: '0192f7a0-0000-7000-8000-0000000000a1', bytes: fixedBytes(32, 0x21) }
const DAY_MS = 24 * 60 * 60 * 1000

describe.each(providers)('device keys ($name)', (provider) => {
  /** A holder in memory, with a wrapping key whose bytes the test chooses. */
  function memoryHolder(wrappingKeyBytes = fixedBytes(32, 0x42)): DeviceKeyHolder & {
    entries: Map<string, DeviceKeyEntry>
  } {
    const entries = new Map<string, DeviceKeyEntry>()
    return {
      entries,
      wrappingKey: async () => rawDeviceWrappingKey(provider, wrappingKeyBytes),
      read: async (id) => entries.get(id) ?? null,
      write: async (entry) => void entries.set(entry.accountId, entry),
      delete: async (id) => void entries.delete(id),
      accountIds: async () => [...entries.keys()],
    }
  }

  test('a kept key opens again, and a forgotten one does not', async () => {
    const holder = memoryHolder()
    await keepAccountKeyOnDevice(provider, holder, { accountId, accountKey, lifetimeMs: DAY_MS })
    const opened = await openAccountKeyOnDevice(holder, accountId)
    expect(opened?.id).toBe(accountKey.id)
    expect(equalBytes(opened!.bytes, accountKey.bytes)).toBe(true)

    await forgetAccountKeyOnDevice(holder, accountId)
    expect(await openAccountKeyOnDevice(holder, accountId)).toBeNull()
  })

  test('an expired entry is deleted unread; an entry with no expiry stays', async () => {
    const holder = memoryHolder()
    await keepAccountKeyOnDevice(provider, holder, { accountId, accountKey, lifetimeMs: DAY_MS, now: 0 })
    expect(await openAccountKeyOnDevice(holder, accountId, { now: DAY_MS + 1 })).toBeNull()
    expect(holder.entries.size).toBe(0)

    await keepAccountKeyOnDevice(provider, holder, { accountId, accountKey })
    expect(holder.entries.get(accountId)?.expiresAt).toBeNull()
    expect(await openAccountKeyOnDevice(holder, accountId, { now: 100 * 365 * DAY_MS })).not.toBeNull()
  })

  test('an entry moved to another account, or with an edited expiry, does not open', async () => {
    const holder = memoryHolder()
    await keepAccountKeyOnDevice(provider, holder, { accountId, accountKey, lifetimeMs: DAY_MS })
    const entry = holder.entries.get(accountId)!

    holder.entries.set(otherAccountId, { ...entry, accountId: otherAccountId })
    expect(await openAccountKeyOnDevice(holder, otherAccountId)).toBeNull()

    holder.entries.set(accountId, { ...entry, expiresAt: null })
    expect(await openAccountKeyOnDevice(holder, accountId)).toBeNull()
    // The entry that did not open is gone.
    expect(holder.entries.has(accountId)).toBe(false)
  })

  test('a new wrapping key leaves the old entries unopened', async () => {
    const entries = new Map<string, DeviceKeyEntry>()
    const first = { ...memoryHolder(fixedBytes(32, 0x01)), entries }
    await keepAccountKeyOnDevice(provider, first, { accountId, accountKey })
    const second = memoryHolder(fixedBytes(32, 0x02))
    second.entries.set(accountId, entries.get(accountId)!)
    expect(await openAccountKeyOnDevice(second, accountId)).toBeNull()
  })

  test('only the account that signs in keeps its key', async () => {
    const holder = memoryHolder()
    await keepAccountKeyOnDevice(provider, holder, { accountId, accountKey })
    await keepAccountKeyOnDevice(provider, holder, { accountId: otherAccountId, accountKey })
    await keepOnlyAccountOnDevice(holder, accountId)
    expect(await holder.accountIds()).toEqual([accountId])
  })
})

describe.runIf(typeof indexedDB !== 'undefined')('IndexedDB device key holder', () => {
  test('keeps a non-extractable wrapping key and opens the entry again', async () => {
    const [provider] = providers
    const databaseName = `tashfir-test-${crypto.randomUUID()}`
    const holder = new IndexedDbDeviceKeyHolder(databaseName)
    await keepAccountKeyOnDevice(provider!, holder, { accountId, accountKey, lifetimeMs: DAY_MS })

    // A second holder on the same database is another tab, or the page after a reload.
    const opened = await openAccountKeyOnDevice(new IndexedDbDeviceKeyHolder(databaseName), accountId)
    expect(equalBytes(opened!.bytes, accountKey.bytes)).toBe(true)

    const stored = await new Promise<CryptoKey>((resolve, reject) => {
      const request = indexedDB.open(databaseName)
      request.onsuccess = () => {
        const get = request.result.transaction('wrapping-key').objectStore('wrapping-key').get('device')
        get.onsuccess = () => resolve(get.result as CryptoKey)
        get.onerror = () => reject(get.error)
      }
    })
    expect(stored.extractable).toBe(false)
    await expect(crypto.subtle.exportKey('raw', stored)).rejects.toThrow()

    await forgetAccountKeyOnDevice(holder, accountId)
    expect(await holder.accountIds()).toEqual([])
  })
})
