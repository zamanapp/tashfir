import { describe, expect, test } from 'vitest'
import { utf8 } from '../src/bytes.ts'
import { generateSymmetricKey, openValue, sealValue, unwrapKey, wrapKey } from '../src/envelope.ts'
import { generateKemKeyPair, unwrapKeyWithSecretKey, wrapKeyToPublicKey } from '../src/hpke.ts'
import { generateSigningKeyPair, sign, verify } from '../src/signature.ts'
import { decryptFile, encryptFile } from '../src/stream.ts'
import { patternBytes } from './fixtures.ts'
import { providers } from './providers.ts'

const context = {
  purpose: 'field' as const,
  table: 'events',
  blob: 'details',
  rowId: '0192f7a0-0000-7000-8000-0000000000cc',
}

// Each pair: one runtime writes with fresh randomness, the other reads. In the browser project
// only the web provider runs, so there is no pair.
const pairs = providers.flatMap((writer) =>
  providers.filter((reader) => reader !== writer).map((reader) => ({ writer, reader }))
)

describe.skipIf(pairs.length === 0)('cross-runtime', () => {
  test.each(pairs)('$writer.name writes, $reader.name reads', async ({ writer, reader }) => {
    const contentKey = generateSymmetricKey(writer)
    const value = { title: 'Jumuah', start: '2026-11-13T12:30:00Z', guests: ['bilal@zaman.app'] }
    expect(
      await openValue(
        reader,
        contentKey,
        await sealValue(writer, contentKey, value, context),
        context
      )
    ).toEqual(value)

    const spaceKey = generateSymmetricKey(writer)
    expect(
      await unwrapKey(reader, spaceKey, await wrapKey(writer, spaceKey, contentKey), contentKey.id)
    ).toEqual(contentKey)

    const recipient = await generateKemKeyPair(reader)
    const grant = await wrapKeyToPublicKey(writer, recipient, contentKey)
    expect(await unwrapKeyWithSecretKey(reader, recipient, grant, contentKey.id)).toEqual(
      contentKey
    )

    const identity = await generateSigningKeyPair(writer)
    const message = utf8('registry entry')
    const signatureContext = utf8('zaman-registry-v1')
    const signature = await sign(writer, identity.secretKey, message, signatureContext)
    expect(await verify(reader, identity.publicKey, message, signature, signatureContext)).toBe(
      true
    )

    const file = patternBytes(70_000)
    expect(
      await decryptFile(reader, contentKey, await encryptFile(writer, contentKey, file))
    ).toEqual(file)
  })
})
