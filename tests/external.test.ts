import { describe, expect, test } from 'vitest'
import { toHex } from '../src/bytes.ts'
import { hkdfExpand, hkdfExtract } from '../src/hkdf.ts'
import { hpkeKeySchedule } from '../src/hpke.ts'
import { signingPublicKey, verify } from '../src/signature.ts'
import composite from '../vectors/external/composite-rfc10073.json' with { type: 'json' }
import hkdfVector from '../vectors/external/hkdf-rfc5869.json' with { type: 'json' }
import hpkePqFile from '../vectors/external/hpke-pq-05-xwing.json' with { type: 'json' }
import hpkeRfcFile from '../vectors/external/hpke-rfc9180.json' with { type: 'json' }
import xWing from '../vectors/external/xwing-draft-11.json' with { type: 'json' }
import { base64, hex } from './fixtures.ts'
import { providers } from './providers.ts'

const hpkePq = hpkePqFile.vector
const hpkeRfc = hpkeRfcFile.vector
const empty = new Uint8Array(0)

describe.each(providers)('external vectors ($name)', (provider) => {
  test('X-Wing draft-11: public key and decapsulation', async () => {
    for (const vector of xWing.vectors) {
      expect(toHex(await provider.xWingPublicKey(hex(vector.seed)))).toBe(vector.pk)
      expect(toHex(await provider.xWingDecapsulate(hex(vector.ct), hex(vector.seed)))).toBe(
        vector.ss
      )
    }
  })

  test.skipIf(!provider.acceptsInjectedRandomness)(
    'X-Wing draft-11: encapsulation with the eseed',
    async () => {
      for (const vector of xWing.vectors) {
        const result = await provider.xWingEncapsulate(hex(vector.pk), hex(vector.eseed))
        expect(toHex(result.ciphertext)).toBe(vector.ct)
        expect(toHex(result.sharedSecret)).toBe(vector.ss)
      }
    }
  )

  test('RFC 10073 id-MLDSA65-Ed25519-SHA512: keys and signatures', async () => {
    const publicKey = base64(composite.pk)
    const message = base64(composite.m)
    const context = base64(composite.ctx)
    expect(toHex(await signingPublicKey(provider, base64(composite.sk)))).toBe(toHex(publicKey))
    expect(await verify(provider, publicKey, message, base64(composite.s), empty)).toBe(true)
    expect(
      await verify(provider, publicKey, message, base64(composite.sWithContext), context)
    ).toBe(true)
    // The context is bound: the signature with a context fails without it.
    expect(await verify(provider, publicKey, message, base64(composite.sWithContext), empty)).toBe(
      false
    )
  })

  test('RFC 10073: a change in either part fails the composite signature', async () => {
    const publicKey = base64(composite.pk)
    const message = base64(composite.m)
    for (const index of [0, 3309 - 1, 3309, 3373 - 1]) {
      const signature = base64(composite.s)
      signature[index] ^= 0x01
      expect(await verify(provider, publicKey, message, signature, empty), `byte ${index}`).toBe(
        false
      )
    }
  })

  test('draft-ietf-hpke-pq-05 at 0x647a: X-Wing decapsulation and the RFC 9180 key schedule', async () => {
    expect(toHex(await provider.xWingPublicKey(hex(hpkePq.skRm)))).toBe(hpkePq.pkRm)
    const sharedSecret = await provider.xWingDecapsulate(hex(hpkePq.enc), hex(hpkePq.skRm))
    expect(toHex(sharedSecret)).toBe(hpkePq.shared_secret)
    // The AEAD of this vector is ChaCha20-Poly1305 (Nk = 32): only the key schedule is checked.
    const context = await hpkeKeySchedule(
      provider,
      { kemId: hpkePq.kem_id, kdfId: hpkePq.kdf_id, aeadId: hpkePq.aead_id },
      sharedSecret,
      hex(hpkePq.info),
      32
    )
    expect(toHex(context.key)).toBe(hpkePq.key)
    expect(toHex(context.baseNonce)).toBe(hpkePq.base_nonce)
    expect(toHex(context.exporterSecret)).toBe(hpkePq.exporter_secret)
  })

  test('RFC 9180 base mode with HKDF-SHA256 and AES-256-GCM: key schedule and first seal', async () => {
    const context = await hpkeKeySchedule(
      provider,
      { kemId: hpkeRfc.kem_id, kdfId: hpkeRfc.kdf_id, aeadId: hpkeRfc.aead_id },
      hex(hpkeRfc.shared_secret),
      hex(hpkeRfc.info),
      32
    )
    expect(toHex(context.key)).toBe(hpkeRfc.key)
    expect(toHex(context.baseNonce)).toBe(hpkeRfc.base_nonce)
    expect(toHex(context.exporterSecret)).toBe(hpkeRfc.exporter_secret)
    const [first] = hpkeRfc.encryptions
    expect(first.nonce).toBe(hpkeRfc.base_nonce)
    const sealed = await provider.aes256GcmSeal(
      context.key,
      context.baseNonce,
      hex(first.pt),
      hex(first.aad)
    )
    expect(toHex(sealed)).toBe(first.ct)
  })

  test('RFC 5869 HKDF-SHA-256', async () => {
    const prk = await hkdfExtract(provider, hex(hkdfVector.salt), hex(hkdfVector.ikm))
    expect(toHex(prk)).toBe(hkdfVector.prk)
    expect(toHex(await hkdfExpand(provider, prk, hex(hkdfVector.info), hkdfVector.length))).toBe(
      hkdfVector.okm
    )
  })
})
