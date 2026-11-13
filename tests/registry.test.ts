import { describe, expect, test } from 'vitest'
import { generateKemKeyPair } from '../src/hpke.ts'
import {
  appendRegistryEntry,
  decodeRegistryEntry,
  emptyRegistryChain,
  encodeRegistryEntry,
  registryEntryHash,
  replayRegistryChain,
  signRegistryEntry,
  type RegistryChain,
  type RegistryEntry,
  type SignedRegistryEntry,
} from '../src/registry.ts'
import { encodeCbor } from '../src/cbor.ts'
import { generateSigningKeyPair, type SigningKeyPair } from '../src/signature.ts'
import type { CryptoProvider } from '../src/provider.ts'
import { errorCode } from './fixtures.ts'
import { providers } from './providers.ts'

const accountId = '0192f7a0-0000-7000-8000-0000000000a1'
const otherAccountId = '0192f7a0-0000-7000-8000-0000000000a2'
const identityKeyId = '0192f7a0-0000-7000-8000-0000000000b1'
const kemKeyId = '0192f7a0-0000-7000-8000-0000000000b2'
const rotatedIdentityKeyId = '0192f7a0-0000-7000-8000-0000000000b3'
const resetIdentityKeyId = '0192f7a0-0000-7000-8000-0000000000b4'

async function signed(
  provider: CryptoProvider,
  signer: SigningKeyPair,
  entry: RegistryEntry
): Promise<SignedRegistryEntry> {
  const entryBytes = encodeRegistryEntry(entry)
  return { entryBytes, signature: await signRegistryEntry(provider, signer.secretKey, entryBytes) }
}

function publishEntry(
  chain: RegistryChain,
  fields: Pick<RegistryEntry, 'keyId' | 'purpose' | 'publicKey' | 'signerKeyId'> &
    Partial<RegistryEntry>
): RegistryEntry {
  return {
    formatVersion: 1,
    accountId: chain.accountId,
    sequence: chain.nextSequence,
    previousHash: chain.headHash,
    kind: 'publish',
    algorithm: fields.purpose === 'identity' ? 'mldsa65-ed25519' : 'xwing-draft-11',
    revocationReason: null,
    ...fields,
  }
}

function revokeEntry(
  chain: RegistryChain,
  fields: Pick<RegistryEntry, 'keyId' | 'purpose' | 'signerKeyId'>
): RegistryEntry {
  return {
    formatVersion: 1,
    accountId: chain.accountId,
    sequence: chain.nextSequence,
    previousHash: chain.headHash,
    kind: 'revoke',
    algorithm: null,
    publicKey: null,
    revocationReason: 'superseded',
    ...fields,
  }
}

describe('registry entry encoding', () => {
  const entry: RegistryEntry = {
    formatVersion: 1,
    accountId,
    sequence: 1,
    previousHash: new Uint8Array(32).fill(7),
    kind: 'revoke',
    keyId: kemKeyId,
    purpose: 'account-kem',
    algorithm: null,
    publicKey: null,
    revocationReason: 'lost_device',
    signerKeyId: identityKeyId,
  }

  test('round trips, and the format version is the first field', () => {
    const bytes = encodeRegistryEntry(entry)
    // A map header, then key 0 and the value 1.
    expect([...bytes.subarray(1, 3)]).toEqual([0x00, 0x01])
    expect(decodeRegistryEntry(bytes)).toEqual(entry)
    expect(encodeRegistryEntry(decodeRegistryEntry(bytes))).toEqual(bytes)
  })

  test('rejects an unknown field and a missing field', () => {
    const withExtra = new Map<number, unknown>([[0, 1], [99, 'x']])
    expect(errorCode(() => decodeRegistryEntry(encodeCbor(withExtra)))).toBe('E_MALFORMED')
    expect(errorCode(() => decodeRegistryEntry(encodeCbor(new Map([[0, 1]]))))).toBe('E_MALFORMED')
  })

  test('rejects an unknown format version', () => {
    expect(errorCode(() => encodeRegistryEntry({ ...entry, formatVersion: 2 }))).toBe(
      'E_UNKNOWN_VERSION'
    )
  })

  test('rejects fields that do not fit the kind', () => {
    expect(
      errorCode(() => encodeRegistryEntry({ ...entry, publicKey: new Uint8Array(1216) }))
    ).toBe('E_REGISTRY_REJECTED')
    expect(errorCode(() => encodeRegistryEntry({ ...entry, previousHash: null }))).toBe(
      'E_REGISTRY_REJECTED'
    )
    expect(
      errorCode(() =>
        encodeRegistryEntry({
          ...entry,
          kind: 'publish',
          revocationReason: null,
          algorithm: 'mldsa65-ed25519',
          publicKey: new Uint8Array(1216),
        })
      )
    ).toBe('E_REGISTRY_REJECTED')
  })
})

describe.each(providers)('registry chain ($name)', (provider) => {
  test('a full life: publish, rotate, revoke, reset', async () => {
    const identity = await generateSigningKeyPair(provider)
    const kem = await generateKemKeyPair(provider)
    const rotatedIdentity = await generateSigningKeyPair(provider)
    const resetIdentity = await generateSigningKeyPair(provider)
    const entries: SignedRegistryEntry[] = []

    let chain = emptyRegistryChain(accountId)
    const append = async (signer: SigningKeyPair, entry: RegistryEntry) => {
      const signedEntry = await signed(provider, signer, entry)
      const result = await appendRegistryEntry(provider, chain, signedEntry)
      expect(result.entryHash).toEqual(await registryEntryHash(provider, signedEntry.entryBytes))
      chain = result.chain
      entries.push(signedEntry)
    }

    await append(
      identity,
      publishEntry(chain, {
        keyId: identityKeyId,
        purpose: 'identity',
        publicKey: identity.publicKey,
        signerKeyId: identityKeyId,
      })
    )
    await append(
      identity,
      publishEntry(chain, {
        keyId: kemKeyId,
        purpose: 'account-kem',
        publicKey: kem.publicKey,
        signerKeyId: identityKeyId,
      })
    )
    // A rotation: the old identity key signs the new one, then the new one revokes the old.
    await append(
      identity,
      publishEntry(chain, {
        keyId: rotatedIdentityKeyId,
        purpose: 'identity',
        publicKey: rotatedIdentity.publicKey,
        signerKeyId: identityKeyId,
      })
    )
    await append(
      rotatedIdentity,
      revokeEntry(chain, {
        keyId: identityKeyId,
        purpose: 'identity',
        signerKeyId: rotatedIdentityKeyId,
      })
    )
    expect(chain.keys.get(identityKeyId)?.revocation).toEqual({ reason: 'superseded', sequence: 3 })
    expect(chain.keys.get(kemKeyId)?.revocation).toBeNull()

    await append(resetIdentity, {
      ...publishEntry(chain, {
        keyId: resetIdentityKeyId,
        purpose: 'identity',
        publicKey: resetIdentity.publicKey,
        signerKeyId: resetIdentityKeyId,
      }),
      kind: 'reset',
    })
    expect(chain.nextSequence).toBe(5)
    expect(chain.keys.get(kemKeyId)?.revocation).toEqual({ reason: 'reset', sequence: 4 })
    expect(chain.keys.get(rotatedIdentityKeyId)?.revocation?.reason).toBe('reset')
    expect(chain.keys.get(resetIdentityKeyId)?.revocation).toBeNull()

    const replayed = await replayRegistryChain(provider, accountId, entries)
    expect(replayed.headHash).toEqual(chain.headHash)
    expect([...replayed.keys.keys()]).toEqual([...chain.keys.keys()])
  })

  describe('rejections', () => {
    async function startedChain() {
      const identity = await generateSigningKeyPair(provider)
      const first = await signed(
        provider,
        identity,
        publishEntry(emptyRegistryChain(accountId), {
          keyId: identityKeyId,
          purpose: 'identity',
          publicKey: identity.publicKey,
          signerKeyId: identityKeyId,
        })
      )
      const { chain } = await appendRegistryEntry(provider, emptyRegistryChain(accountId), first)
      const kem = await generateKemKeyPair(provider)
      const kemEntry = publishEntry(chain, {
        keyId: kemKeyId,
        purpose: 'account-kem',
        publicKey: kem.publicKey,
        signerKeyId: identityKeyId,
      })
      return { identity, chain, kemEntry }
    }

    const rejectedCode = async (chain: RegistryChain, entry: SignedRegistryEntry) =>
      appendRegistryEntry(provider, chain, entry).then(
        () => undefined,
        (error: { code?: string }) => error.code
      )

    test('a first entry that does not sign itself', async () => {
      const identity = await generateSigningKeyPair(provider)
      const kem = await generateKemKeyPair(provider)
      const entry = publishEntry(emptyRegistryChain(accountId), {
        keyId: kemKeyId,
        purpose: 'account-kem',
        publicKey: kem.publicKey,
        signerKeyId: identityKeyId,
      })
      expect(
        await rejectedCode(emptyRegistryChain(accountId), await signed(provider, identity, entry))
      ).toBe('E_REGISTRY_REJECTED')
    })

    test('a wrong sequence, a wrong previous hash, another account', async () => {
      const { identity, chain, kemEntry } = await startedChain()
      for (const changed of [
        { ...kemEntry, sequence: 2 },
        { ...kemEntry, previousHash: new Uint8Array(32) },
        { ...kemEntry, accountId: otherAccountId },
      ]) {
        expect(await rejectedCode(chain, await signed(provider, identity, changed))).toBe(
          'E_REGISTRY_REJECTED'
        )
      }
    })

    test('a signature of another key, and changed bytes', async () => {
      const { chain, kemEntry, identity } = await startedChain()
      const stranger = await generateSigningKeyPair(provider)
      expect(await rejectedCode(chain, await signed(provider, stranger, kemEntry))).toBe(
        'E_REGISTRY_REJECTED'
      )
      const good = await signed(provider, identity, kemEntry)
      const otherEntryBytes = encodeRegistryEntry({ ...kemEntry, keyId: rotatedIdentityKeyId })
      expect(
        await rejectedCode(chain, { entryBytes: otherEntryBytes, signature: good.signature })
      ).toBe('E_REGISTRY_REJECTED')
    })

    test('a self-signed publish after the first entry, and a known key ID', async () => {
      const { chain, identity } = await startedChain()
      const extraIdentity = await generateSigningKeyPair(provider)
      const selfSigned = publishEntry(chain, {
        keyId: rotatedIdentityKeyId,
        purpose: 'identity',
        publicKey: extraIdentity.publicKey,
        signerKeyId: rotatedIdentityKeyId,
      })
      expect(await rejectedCode(chain, await signed(provider, extraIdentity, selfSigned))).toBe(
        'E_REGISTRY_REJECTED'
      )
      const known = publishEntry(chain, {
        keyId: identityKeyId,
        purpose: 'identity',
        publicKey: extraIdentity.publicKey,
        signerKeyId: identityKeyId,
      })
      expect(await rejectedCode(chain, await signed(provider, identity, known))).toBe(
        'E_REGISTRY_REJECTED'
      )
    })

    test('a revoked signer, and a revoke of an unknown key', async () => {
      const { chain: started, identity } = await startedChain()
      const rotated = await generateSigningKeyPair(provider)
      let chain = (
        await appendRegistryEntry(
          provider,
          started,
          await signed(
            provider,
            identity,
            publishEntry(started, {
              keyId: rotatedIdentityKeyId,
              purpose: 'identity',
              publicKey: rotated.publicKey,
              signerKeyId: identityKeyId,
            })
          )
        )
      ).chain
      chain = (
        await appendRegistryEntry(
          provider,
          chain,
          await signed(
            provider,
            rotated,
            revokeEntry(chain, {
              keyId: identityKeyId,
              purpose: 'identity',
              signerKeyId: rotatedIdentityKeyId,
            })
          )
        )
      ).chain

      const kem = await generateKemKeyPair(provider)
      const byRevokedKey = publishEntry(chain, {
        keyId: kemKeyId,
        purpose: 'account-kem',
        publicKey: kem.publicKey,
        signerKeyId: identityKeyId,
      })
      expect(await rejectedCode(chain, await signed(provider, identity, byRevokedKey))).toBe(
        'E_REGISTRY_REJECTED'
      )
      const unknownKey = revokeEntry(chain, {
        keyId: kemKeyId,
        purpose: 'account-kem',
        signerKeyId: rotatedIdentityKeyId,
      })
      expect(await rejectedCode(chain, await signed(provider, rotated, unknownKey))).toBe(
        'E_REGISTRY_REJECTED'
      )
    })
  })
})
