/**
 * Writes the known-answer vectors of the current suite to `vectors/known-answer/`. The inputs and
 * the randomness are fixed, so the output never changes for a suite. Run it only to add a new
 * suite or a new kind of vector, never to make a failing test pass: a changed byte in an
 * existing vector means that old ciphertexts no longer open.
 */
import { writeFileSync } from 'node:fs'
import { encodeCbor } from '../src/cbor.ts'
import { toHex } from '../src/bytes.ts'
import { sealBytesWith } from '../src/envelope.ts'
import { wrapKeyToPublicKeyWith } from '../src/hpke.ts'
import { WebCryptoProvider } from '../src/providers/web.ts'
import { signingPublicKey, signWith } from '../src/signature.ts'
import { encryptFileWith } from '../src/stream.ts'
import {
  encodeRegistryEntry,
  registryEntryHash,
  signRegistryEntryWith,
  type RegistryEntry,
} from '../src/registry.ts'
import { storageKey } from '../src/storage_key.ts'
import { passwordUnlockKey } from '../src/account_keys.ts'
import {
  recoveryKeyToCode,
  recoveryKeyToWords,
  recoveryProof,
  recoveryQrPayload,
  recoveryUnlockKey,
} from '../src/recovery.ts'
import { currentSuite } from '../src/suites.ts'
import { fixedBytes, patternBytes } from '../tests/fixtures.ts'

const provider = new WebCryptoProvider()
const suite = currentSuite()

const contentKey = { id: '0192f7a0-0000-7000-8000-000000000001', bytes: fixedBytes(32, 0x10) }
const wrappingKey = { id: '0192f7a0-0000-7000-8000-000000000002', bytes: fixedBytes(32, 0x40) }
const fieldContext = {
  purpose: 'field' as const,
  table: 'emails',
  blob: 'header',
  rowId: '0192f7a0-0000-7000-8000-0000000000aa',
}
const fieldValue = {
  subject: 'Salam',
  from: ['amine@zaman.app'],
  to: ['bilal@zaman.app'],
  size: 1024,
}
const fieldNonce = fixedBytes(12, 0xa0)
const wrapNonce = fixedBytes(12, 0xb0)

const recipientSecretKey = fixedBytes(32, 0x70)
const recipient = {
  id: '0192f7a0-0000-7000-8000-000000000003',
  publicKey: await provider.xWingPublicKey(recipientSecretKey),
}
const encapsulationRandomness = fixedBytes(64, 0xc0)

const signingSecretKey = fixedBytes(64, 0x20)
const message = new TextEncoder().encode('Invitation to space 0192f7a0-0000-7000-8000-0000000000bb')
const signatureContext = new TextEncoder().encode('zaman-invitation-v1')
const signatureRandomness = fixedBytes(32, 0xd0)

const fileKey = { id: '0192f7a0-0000-7000-8000-000000000004', bytes: fixedBytes(32, 0x90) }
const noncePrefix = fixedBytes(7, 0xe0)
const fileLengths = [
  0,
  100,
  suite.fileSegmentSize,
  suite.fileSegmentSize + 1,
  3 * suite.fileSegmentSize - 7,
]

const registryAccountId = '0192f7a0-0000-7000-8000-0000000000c1'
const registrySigningKey = {
  id: '0192f7a0-0000-7000-8000-0000000000c2',
  secretKey: fixedBytes(64, 0x30),
}
const registryKem = { id: '0192f7a0-0000-7000-8000-0000000000c3', secretKey: fixedBytes(32, 0x58) }
const registrySignatureRandomness = [fixedBytes(32, 0xd8), fixedBytes(32, 0xe8)]
const registrySigningPublicKey = await signingPublicKey(provider, registrySigningKey.secretKey)
const registryKemPublicKey = await provider.xWingPublicKey(registryKem.secretKey)

const registryEntries: RegistryEntry[] = [
  {
    formatVersion: 1,
    accountId: registryAccountId,
    sequence: 0,
    previousHash: null,
    kind: 'publish',
    keyId: registrySigningKey.id,
    purpose: 'signing',
    algorithm: 'mldsa65-ed25519',
    publicKey: registrySigningPublicKey,
    revocationReason: null,
    signerKeyId: registrySigningKey.id,
  },
]
const firstEntryBytes = encodeRegistryEntry(registryEntries[0]!)
registryEntries.push({
  formatVersion: 1,
  accountId: registryAccountId,
  sequence: 1,
  previousHash: await registryEntryHash(provider, firstEntryBytes),
  kind: 'publish',
  keyId: registryKem.id,
  purpose: 'encryption',
  algorithm: 'xwing-draft-11',
  publicKey: registryKemPublicKey,
  revocationReason: null,
  signerKeyId: registrySigningKey.id,
})

const exportKey = fixedBytes(64, 0x41)
const recoveryKey = fixedBytes(32, 0x10)
const unlockKeyId = '0192f7a0-0000-7000-8000-0000000000d1'

const vectors = {
  description:
    'Known-answer vectors of suite 0x01. Every runtime must give these bytes for these inputs, or open them.',
  suiteId: suite.id,
  field: {
    key: { id: contentKey.id, bytes: toHex(contentKey.bytes) },
    context: fieldContext,
    value: fieldValue,
    cbor: toHex(encodeCbor(fieldValue)),
    nonce: toHex(fieldNonce),
    envelope: toHex(
      await sealBytesWith(provider, contentKey, encodeCbor(fieldValue), fieldContext, {
        nonce: fieldNonce,
      })
    ),
  },
  keyWrap: {
    wrappingKey: { id: wrappingKey.id, bytes: toHex(wrappingKey.bytes) },
    key: { id: contentKey.id, bytes: toHex(contentKey.bytes) },
    nonce: toHex(wrapNonce),
    envelope: toHex(
      await sealBytesWith(
        provider,
        wrappingKey,
        contentKey.bytes,
        { purpose: 'key-wrap', wrappedKeyId: contentKey.id },
        { nonce: wrapNonce }
      )
    ),
  },
  publicKeyWrap: {
    recipient: {
      id: recipient.id,
      secretKey: toHex(recipientSecretKey),
      publicKey: toHex(recipient.publicKey),
    },
    key: { id: contentKey.id, bytes: toHex(contentKey.bytes) },
    randomness: toHex(encapsulationRandomness),
    wrap: toHex(
      await wrapKeyToPublicKeyWith(provider, recipient, contentKey, {
        randomness: encapsulationRandomness,
      })
    ),
  },
  signature: {
    secretKey: toHex(signingSecretKey),
    publicKey: toHex(await signingPublicKey(provider, signingSecretKey)),
    message: toHex(message),
    context: toHex(signatureContext),
    randomness: toHex(signatureRandomness),
    signature: toHex(
      await signWith(provider, signingSecretKey, message, signatureContext, {
        randomness: signatureRandomness,
      })
    ),
  },
  registry: {
    accountId: registryAccountId,
    signingKey: {
      id: registrySigningKey.id,
      secretKey: toHex(registrySigningKey.secretKey),
      publicKey: toHex(registrySigningPublicKey),
    },
    kem: {
      id: registryKem.id,
      secretKey: toHex(registryKem.secretKey),
      publicKey: toHex(registryKemPublicKey),
    },
    entries: await Promise.all(
      registryEntries.map(async (entry, index) => {
        const entryBytes = encodeRegistryEntry(entry)
        const randomness = registrySignatureRandomness[index]!
        return {
          entryBytes: toHex(entryBytes),
          hash: toHex(await registryEntryHash(provider, entryBytes)),
          randomness: toHex(randomness),
          signature: toHex(
            await signRegistryEntryWith(provider, registrySigningKey.secretKey, entryBytes, {
              randomness,
            })
          ),
        }
      })
    ),
  },
  unlockKeys: {
    description:
      'The keys of the unlock wraps of the account key: HKDF-SHA-256 of the OPAQUE export key, and of the recovery key.',
    exportKey: toHex(exportKey),
    passwordUnlockKey: toHex((await passwordUnlockKey(provider, exportKey, unlockKeyId)).bytes),
    recoveryKey: toHex(recoveryKey),
    recoveryUnlockKey: toHex((await recoveryUnlockKey(provider, recoveryKey, unlockKeyId)).bytes),
    recoveryProof: toHex(await recoveryProof(provider, recoveryKey)),
  },
  recoveryKeyForms: {
    recoveryKey: toHex(recoveryKey),
    words: recoveryKeyToWords(recoveryKey),
    code: await recoveryKeyToCode(provider, recoveryKey),
    qrPayload: await recoveryQrPayload(provider, recoveryKey),
  },
  files: {
    key: { id: fileKey.id, bytes: toHex(fileKey.bytes) },
    noncePrefix: toHex(noncePrefix),
    plaintext: 'byte i of a plaintext of length n is i % 251',
    cases: await Promise.all(
      fileLengths.map(async (length) => {
        const encrypted = await encryptFileWith(provider, fileKey, patternBytes(length), {
          noncePrefix,
        })
        return {
          length,
          encryptedLength: encrypted.length,
          storageKey: storageKey(encrypted),
          // Small files are written out; large ones are pinned by their BLAKE3 storage key.
          encrypted: length <= 100 ? toHex(encrypted) : undefined,
        }
      })
    ),
  },
}

const target = new URL(
  `../vectors/known-answer/suite-${suite.id.toString(16).padStart(2, '0')}.json`,
  import.meta.url
)
writeFileSync(target, JSON.stringify(vectors, null, 2) + '\n')
console.log(`Wrote ${target.pathname}`)
