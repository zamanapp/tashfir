import { describe, expect, test } from 'vitest'
import { version as uuidVersion } from 'uuid'
import { bytesToUuid, concatBytes, fromHex, newKeyId } from '../src/bytes.ts'
import { decodeCbor, encodeCbor } from '../src/cbor.ts'
import {
  generateSymmetricKey,
  HEADER_LENGTH,
  openBytes,
  readEnvelopeHeader,
  sealBytes,
  unwrapKey,
  wrapKey,
} from '../src/envelope.ts'
import { generateKemKeyPair, unwrapKeyWithSecretKey, wrapKeyToPublicKey } from '../src/hpke.ts'
import { pad, unpad } from '../src/padding.ts'
import {
  decryptFile,
  encryptFile,
  FILE_HEADER_LENGTH,
  openFileSegment,
  segmentByteRange,
} from '../src/stream.ts'
import { errorCode, patternBytes } from './fixtures.ts'
import { providers } from './providers.ts'

const context = {
  purpose: 'field' as const,
  table: 'emails',
  blob: 'body',
  rowId: '0192f7a0-0000-7000-8000-0000000000dd',
}

describe('padding', () => {
  test('pads with 0x80 and strips any number of zeros', () => {
    expect(pad(Uint8Array.of(1, 2))).toEqual(Uint8Array.of(1, 2, 0x80))
    expect(unpad(Uint8Array.of(1, 2, 0x80, 0, 0, 0))).toEqual(Uint8Array.of(1, 2))
    expect(unpad(Uint8Array.of(0x80))).toEqual(new Uint8Array(0))
  })

  test('rejects a plaintext with no marker', () => {
    expect(errorCode(() => unpad(Uint8Array.of(1, 2, 0)))).toBe('E_MALFORMED')
    expect(errorCode(() => unpad(new Uint8Array(0)))).toBe('E_MALFORMED')
  })
})

describe('CBOR', () => {
  test('encodes map keys in deterministic order', () => {
    expect(encodeCbor({ b: 1, a: 2 })).toEqual(encodeCbor({ a: 2, b: 1 }))
  })

  test('rejects a non-deterministic encoding of the same value', () => {
    // {"a": 1} with the integer 1 in a 1-byte argument (0x18 0x01) instead of the short form.
    expect(errorCode(() => decodeCbor(fromHex('a161611801')))).toBe('E_MALFORMED')
    expect(decodeCbor(fromHex('a1616101'))).toEqual({ a: 1 })
  })
})

test('a new key UUID is version 7 and takes its random bytes from the caller', () => {
  const keyId = newKeyId(new Uint8Array(16).fill(0xff))
  expect(uuidVersion(keyId)).toBe(7)
  expect(keyId.endsWith('-ffffffffffff')).toBe(true)
  expect(errorCode(() => newKeyId(new Uint8Array(10)))).toBe('E_INVALID_INPUT')
})

test('a header with bytes that are not a UUID is malformed', () => {
  expect(errorCode(() => bytesToUuid(new Uint8Array(16).fill(0x11)))).toBe('E_MALFORMED')
})

describe.each(providers)('envelope ($name)', (provider) => {
  test('a change of any byte fails the open', async () => {
    const key = generateSymmetricKey(provider)
    const envelope = await sealBytes(provider, key, patternBytes(40), context)
    // Skip the key UUID: a change there is a key mismatch, tested below.
    for (const index of [0, 1, 18, HEADER_LENGTH - 1, HEADER_LENGTH, envelope.length - 1]) {
      const changed = envelope.slice()
      changed[index] ^= 0x01
      await expect(openBytes(provider, key, changed, context), `byte ${index}`).rejects.toThrow()
    }
  })

  test('the header names the key, and a different key is refused before decryption', async () => {
    const key = generateSymmetricKey(provider)
    const envelope = await sealBytes(provider, key, patternBytes(8), context)
    expect(readEnvelopeHeader(envelope).keyId).toBe(key.id)
    await expect(
      openBytes(provider, generateSymmetricKey(provider), envelope, context)
    ).rejects.toMatchObject({
      code: 'E_KEY_MISMATCH',
    })
  })

  test('an unknown version or suite fails closed', async () => {
    const key = generateSymmetricKey(provider)
    const envelope = await sealBytes(provider, key, patternBytes(8), context)
    const unknownVersion = envelope.slice()
    unknownVersion[0] = 0x02
    await expect(openBytes(provider, key, unknownVersion, context)).rejects.toMatchObject({
      code: 'E_UNKNOWN_VERSION',
    })
    const unknownSuite = envelope.slice()
    unknownSuite[1] = 0x7f
    await expect(openBytes(provider, key, unknownSuite, context)).rejects.toMatchObject({
      code: 'E_UNKNOWN_SUITE',
    })
  })

  test('a field ciphertext does not open as a key wrap, nor in another blob', async () => {
    const key = generateSymmetricKey(provider)
    const inner = generateSymmetricKey(provider)
    const wrap = await wrapKey(provider, key, inner)
    await expect(openBytes(provider, key, wrap, context)).rejects.toMatchObject({
      code: 'E_DECRYPT_FAILED',
    })
    await expect(
      unwrapKey(provider, key, wrap, generateSymmetricKey(provider).id)
    ).rejects.toMatchObject({
      code: 'E_DECRYPT_FAILED',
    })
    const envelope = await sealBytes(provider, key, patternBytes(8), context)
    await expect(
      openBytes(provider, key, envelope, { ...context, blob: 'header' })
    ).rejects.toMatchObject({
      code: 'E_DECRYPT_FAILED',
    })
  })

  test('a public-key wrap opens only with its key pair and for its wrapped key', async () => {
    const recipient = await generateKemKeyPair(provider)
    const other = await generateKemKeyPair(provider)
    const key = generateSymmetricKey(provider)
    const wrap = await wrapKeyToPublicKey(provider, recipient, key)
    await expect(unwrapKeyWithSecretKey(provider, other, wrap, key.id)).rejects.toMatchObject({
      code: 'E_KEY_MISMATCH',
    })
    // The other key pair under the UUID of the recipient: the HPKE info matches, the key does not.
    await expect(
      unwrapKeyWithSecretKey(
        provider,
        { id: recipient.id, secretKey: other.secretKey },
        wrap,
        key.id
      )
    ).rejects.toMatchObject({ code: 'E_DECRYPT_FAILED' })
    await expect(
      unwrapKeyWithSecretKey(provider, recipient, wrap, generateSymmetricKey(provider).id)
    ).rejects.toMatchObject({ code: 'E_DECRYPT_FAILED' })
  })
})

describe.each(providers)('files ($name)', (provider) => {
  const segment = 64 * 1024

  test('round trip at the segment edges', async () => {
    const key = generateSymmetricKey(provider)
    for (const length of [0, 1, segment - 1, segment, segment + 1, 2 * segment]) {
      const plaintext = patternBytes(length)
      expect(await decryptFile(provider, key, await encryptFile(provider, key, plaintext))).toEqual(
        plaintext
      )
    }
  })

  test('a cut, a reorder or an extra segment fails', async () => {
    const key = generateSymmetricKey(provider)
    const encrypted = await encryptFile(provider, key, patternBytes(2 * segment + 10))
    const first = segmentByteRange(0, encrypted.length)
    const second = segmentByteRange(1, encrypted.length)
    // Cut after a full segment: that segment has no last flag.
    await expect(
      decryptFile(provider, key, encrypted.subarray(0, second.end))
    ).rejects.toMatchObject({
      code: 'E_DECRYPT_FAILED',
    })
    const header = encrypted.subarray(0, FILE_HEADER_LENGTH)
    const reordered = concatBytes(
      header,
      encrypted.subarray(second.start, second.end),
      encrypted.subarray(first.start, first.end),
      encrypted.subarray(second.end)
    )
    await expect(decryptFile(provider, key, reordered)).rejects.toMatchObject({
      code: 'E_DECRYPT_FAILED',
    })
    await expect(
      decryptFile(provider, key, concatBytes(encrypted, new Uint8Array(16)))
    ).rejects.toMatchObject({
      code: 'E_DECRYPT_FAILED',
    })
  })

  test('a ranged read opens one segment', async () => {
    const key = generateSymmetricKey(provider)
    const plaintext = patternBytes(3 * segment)
    const encrypted = await encryptFile(provider, key, plaintext)
    const range = segmentByteRange(1, encrypted.length)
    const opened = await openFileSegment(
      provider,
      key,
      encrypted.subarray(0, FILE_HEADER_LENGTH),
      1,
      encrypted.subarray(range.start, range.end),
      range.last
    )
    expect(opened).toEqual(plaintext.subarray(segment, 2 * segment))
  })
})
