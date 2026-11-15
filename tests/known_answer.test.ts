import { describe, expect, test } from 'vitest'
import { toHex } from '../src/bytes.ts'
import { encodeCbor } from '../src/cbor.ts'
import type { EnvelopeContext } from '../src/context.ts'
import { openBytes, openValue, sealBytesWith, unwrapKey } from '../src/envelope.ts'
import { unwrapKeyWithSecretKey, wrapKeyToPublicKeyWith } from '../src/hpke.ts'
import { signingPublicKey, signWith, verify } from '../src/signature.ts'
import { storageKey } from '../src/storage_key.ts'
import { decryptFile, encryptFileWith } from '../src/stream.ts'
import {
  decodeRegistryEntry,
  encodeRegistryEntry,
  registryEntryHash,
  replayRegistryChain,
  signRegistryEntryWith,
} from '../src/registry.ts'
import { passwordUnlockKey } from '../src/account_keys.ts'
import {
  recoveryKeyFromCode,
  recoveryKeyFromQrPayload,
  recoveryKeyFromWords,
  recoveryKeyToCode,
  recoveryKeyToWords,
  recoveryProof,
  recoveryQrPayload,
  recoveryUnlockKey,
} from '../src/recovery.ts'
import vectors from '../vectors/known-answer/suite-01.json' with { type: 'json' }
import { hex, patternBytes } from './fixtures.ts'
import { providers } from './providers.ts'

const key = (value: { id: string; bytes: string }) => ({ id: value.id, bytes: hex(value.bytes) })
const fieldContext = vectors.field.context as EnvelopeContext & { purpose: 'field' }

describe.each(providers)('known-answer vectors of suite 0x01 ($name)', (provider) => {
  test('field blob: CBOR, seal and open', async () => {
    const { field } = vectors
    expect(toHex(encodeCbor(field.value))).toBe(field.cbor)
    const sealed = await sealBytesWith(provider, key(field.key), hex(field.cbor), fieldContext, {
      nonce: hex(field.nonce),
    })
    expect(toHex(sealed)).toBe(field.envelope)
    expect(await openValue(provider, key(field.key), hex(field.envelope), fieldContext)).toEqual(
      field.value
    )
  })

  test('symmetric key wrap', async () => {
    const { keyWrap } = vectors
    const sealed = await sealBytesWith(
      provider,
      key(keyWrap.wrappingKey),
      hex(keyWrap.key.bytes),
      { purpose: 'key-wrap', wrappedKeyId: keyWrap.key.id },
      { nonce: hex(keyWrap.nonce) }
    )
    expect(toHex(sealed)).toBe(keyWrap.envelope)
    const unwrapped = await unwrapKey(
      provider,
      key(keyWrap.wrappingKey),
      hex(keyWrap.envelope),
      keyWrap.key.id
    )
    expect(toHex(unwrapped.bytes)).toBe(keyWrap.key.bytes)
  })

  test('public-key wrap: open', async () => {
    const { publicKeyWrap } = vectors
    expect(toHex(await provider.xWingPublicKey(hex(publicKeyWrap.recipient.secretKey)))).toBe(
      publicKeyWrap.recipient.publicKey
    )
    const unwrapped = await unwrapKeyWithSecretKey(
      provider,
      { id: publicKeyWrap.recipient.id, secretKey: hex(publicKeyWrap.recipient.secretKey) },
      hex(publicKeyWrap.wrap),
      publicKeyWrap.key.id
    )
    expect(toHex(unwrapped.bytes)).toBe(publicKeyWrap.key.bytes)
  })

  test.skipIf(!provider.acceptsInjectedRandomness)(
    'public-key wrap: seal with the eseed',
    async () => {
      const { publicKeyWrap } = vectors
      const wrap = await wrapKeyToPublicKeyWith(
        provider,
        { id: publicKeyWrap.recipient.id, publicKey: hex(publicKeyWrap.recipient.publicKey) },
        key(publicKeyWrap.key),
        { randomness: hex(publicKeyWrap.randomness) }
      )
      expect(toHex(wrap)).toBe(publicKeyWrap.wrap)
    }
  )

  test('signature: public key and verify', async () => {
    const { signature } = vectors
    expect(toHex(await signingPublicKey(provider, hex(signature.secretKey)))).toBe(
      signature.publicKey
    )
    expect(
      await verify(
        provider,
        hex(signature.publicKey),
        hex(signature.message),
        hex(signature.signature),
        hex(signature.context)
      )
    ).toBe(true)
  })

  test.skipIf(!provider.acceptsInjectedRandomness)(
    'signature: sign with the randomness',
    async () => {
      const { signature } = vectors
      const signed = await signWith(
        provider,
        hex(signature.secretKey),
        hex(signature.message),
        hex(signature.context),
        {
          randomness: hex(signature.randomness),
        }
      )
      expect(toHex(signed)).toBe(signature.signature)
    }
  )

  test('files: STREAM bytes, storage key and decryption', async () => {
    const { files } = vectors
    for (const fileCase of files.cases) {
      const plaintext = patternBytes(fileCase.length)
      const encrypted = await encryptFileWith(provider, key(files.key), plaintext, {
        noncePrefix: hex(files.noncePrefix),
      })
      expect(encrypted.length, `length ${fileCase.length}`).toBe(fileCase.encryptedLength)
      expect(storageKey(encrypted), `length ${fileCase.length}`).toBe(fileCase.storageKey)
      if ('encrypted' in fileCase && fileCase.encrypted)
        expect(toHex(encrypted)).toBe(fileCase.encrypted)
      expect(await decryptFile(provider, key(files.key), encrypted)).toEqual(plaintext)
    }
  })

  test('registry: entry bytes, hashes and the chain', async () => {
    const { registry } = vectors
    expect(toHex(await provider.xWingPublicKey(hex(registry.kem.secretKey)))).toBe(
      registry.kem.publicKey
    )
    for (const vectorEntry of registry.entries) {
      const entryBytes = hex(vectorEntry.entryBytes)
      expect(toHex(encodeRegistryEntry(decodeRegistryEntry(entryBytes)))).toBe(
        vectorEntry.entryBytes
      )
      expect(toHex(await registryEntryHash(provider, entryBytes))).toBe(vectorEntry.hash)
    }
    const chain = await replayRegistryChain(
      provider,
      registry.accountId,
      registry.entries.map((vectorEntry) => ({
        entryBytes: hex(vectorEntry.entryBytes),
        signature: hex(vectorEntry.signature),
      }))
    )
    expect(chain.nextSequence).toBe(2)
    expect(toHex(chain.headHash!)).toBe(registry.entries[1]!.hash)
    expect(toHex(chain.keys.get(registry.kem.id)!.publicKey)).toBe(registry.kem.publicKey)
  })

  test.skipIf(!provider.acceptsInjectedRandomness)(
    'registry: sign with the randomness',
    async () => {
      const { registry } = vectors
      for (const vectorEntry of registry.entries) {
        const signature = await signRegistryEntryWith(
          provider,
          hex(registry.signingKey.secretKey),
          hex(vectorEntry.entryBytes),
          { randomness: hex(vectorEntry.randomness) }
        )
        expect(toHex(signature)).toBe(vectorEntry.signature)
      }
    }
  )

  test('unlock keys: password and recovery', async () => {
    const id = '0192f7a0-0000-7000-8000-0000000000d1'
    const { exportKey, recoveryKey } = vectors.unlockKeys
    expect(toHex((await passwordUnlockKey(provider, hex(exportKey), id)).bytes)).toBe(vectors.unlockKeys.passwordUnlockKey)
    expect(toHex((await recoveryUnlockKey(provider, hex(recoveryKey), id)).bytes)).toBe(vectors.unlockKeys.recoveryUnlockKey)
    expect(toHex(await recoveryProof(provider, hex(recoveryKey)))).toBe(vectors.unlockKeys.recoveryProof)
  })

  test('recovery key forms: words, code and QR payload', async () => {
    const forms = vectors.recoveryKeyForms
    const recoveryKey = hex(forms.recoveryKey)
    expect(recoveryKeyToWords(recoveryKey)).toEqual(forms.words)
    expect(await recoveryKeyToCode(provider, recoveryKey)).toBe(forms.code)
    expect(await recoveryQrPayload(provider, recoveryKey)).toBe(forms.qrPayload)
    expect(toHex(recoveryKeyFromWords(forms.words))).toBe(forms.recoveryKey)
    expect(toHex(await recoveryKeyFromCode(provider, forms.code))).toBe(forms.recoveryKey)
    expect(toHex(await recoveryKeyFromQrPayload(provider, forms.qrPayload))).toBe(forms.recoveryKey)
  })

  test('the field envelope does not open in another row', async () => {
    const { field } = vectors
    await expect(
      openBytes(provider, key(field.key), hex(field.envelope), {
        ...fieldContext,
        rowId: '0192f7a0-0000-7000-8000-0000000000ab',
      })
    ).rejects.toMatchObject({ code: 'E_DECRYPT_FAILED' })
  })
})
