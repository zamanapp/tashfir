import type { DeviceKeyEntry, DeviceKeyHolder, DeviceWrappingKey } from '../device_keys.ts'

const ENTRIES = 'entries'
const WRAPPING_KEY = 'wrapping-key'
const WRAPPING_KEY_ID = 'device'

/** WebCrypto types ask for an ArrayBuffer-backed view; ours always are. */
function source(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>
}

/**
 * A wrapping key made by WebCrypto as non-extractable: scripts of the page can use it, but
 * nobody can read its bytes, not even from the devtools. IndexedDB keeps the `CryptoKey` object
 * itself (a structured clone), never its bytes.
 */
export function webCryptoDeviceWrappingKey(key: CryptoKey): DeviceWrappingKey {
  return {
    async seal(nonce, plaintext, associatedData) {
      return new Uint8Array(
        await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv: source(nonce), additionalData: source(associatedData) },
          key,
          source(plaintext)
        )
      )
    },
    async open(nonce, sealed, associatedData) {
      return new Uint8Array(
        await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: source(nonce), additionalData: source(associatedData) },
          key,
          source(sealed)
        )
      )
    },
  }
}

/**
 * The browser holder: one IndexedDB database with the wrapping key of the device and one entry
 * for each account. This is weaker than the keystore of a phone: a person with the unlocked
 * browser profile can use the key while the app runs.
 */
export class IndexedDbDeviceKeyHolder implements DeviceKeyHolder {
  readonly databaseName: string

  constructor(databaseName: string) {
    this.databaseName = databaseName
  }

  #open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(this.databaseName, 1)
      request.onupgradeneeded = () => {
        request.result.createObjectStore(ENTRIES, { keyPath: 'accountId' })
        request.result.createObjectStore(WRAPPING_KEY)
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () => reject(request.error)
    })
  }

  async #run<Result>(
    storeName: string,
    mode: IDBTransactionMode,
    action: (store: IDBObjectStore) => IDBRequest<Result>
  ): Promise<Result> {
    const database = await this.#open()
    try {
      return await new Promise<Result>((resolve, reject) => {
        const transaction = database.transaction(storeName, mode)
        const request = action(transaction.objectStore(storeName))
        transaction.oncomplete = () => resolve(request.result)
        transaction.onerror = () => reject(transaction.error)
        transaction.onabort = () => reject(transaction.error)
      })
    } finally {
      database.close()
    }
  }

  async wrappingKey(): Promise<DeviceWrappingKey> {
    const stored = await this.#run<CryptoKey | undefined>(WRAPPING_KEY, 'readonly', (store) =>
      store.get(WRAPPING_KEY_ID)
    )
    if (stored) return webCryptoDeviceWrappingKey(stored)
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
      'encrypt',
      'decrypt',
    ])
    // `add` fails when another tab stored a key first; then that key is the key of the device.
    try {
      await this.#run(WRAPPING_KEY, 'readwrite', (store) => store.add(key, WRAPPING_KEY_ID))
      return webCryptoDeviceWrappingKey(key)
    } catch {
      const winner = await this.#run<CryptoKey>(WRAPPING_KEY, 'readonly', (store) =>
        store.get(WRAPPING_KEY_ID)
      )
      return webCryptoDeviceWrappingKey(winner)
    }
  }

  async read(accountId: string): Promise<DeviceKeyEntry | null> {
    const entry = await this.#run<DeviceKeyEntry | undefined>(ENTRIES, 'readonly', (store) =>
      store.get(accountId)
    )
    return entry ?? null
  }

  async write(entry: DeviceKeyEntry): Promise<void> {
    await this.#run(ENTRIES, 'readwrite', (store) => store.put(entry))
  }

  async delete(accountId: string): Promise<void> {
    await this.#run(ENTRIES, 'readwrite', (store) => store.delete(accountId))
  }

  async accountIds(): Promise<string[]> {
    const keys = await this.#run<IDBValidKey[]>(ENTRIES, 'readonly', (store) => store.getAllKeys())
    return keys.map(String)
  }
}
