# @zamanapp/tashfir

*Tashfir* (تشفير) is Arabic for encryption.

The crypto formats of Zaman: the envelope of each encrypted field, key wraps, signatures and encrypted files. The formats are written once in TypeScript. Each runtime gives only the primitives, through a `CryptoProvider`.

This README describes the formats and the rules that an auditor needs. The suite registry is in `src/suites.ts`.

Licence: [FSL-1.1-ALv2](./LICENSE.md). Each version becomes Apache-2.0 two years after its release.

## Install

```sh
pnpm add @zamanapp/tashfir
```

Pin the exact version: a new release can add a suite, and every runtime of an app must read the same suites. Node 26 or later (OpenSSL 3.5) for the Node provider.

## Entry points

| Import | Contents |
| ------ | -------- |
| `@zamanapp/tashfir` | The formats: envelope, key wraps, HPKE wraps, composite signatures, STREAM files, CBOR, registry entries and their chain rules, the keys of a new account and their unlock wraps, the recovery key and its written forms, the account key kept on a device (`keepAccountKeyOnDevice`, `openAccountKeyOnDevice` and the `DeviceKeyHolder` interface), the suite registry |
| `@zamanapp/tashfir/node` | `NodeCryptoProvider`: Node `crypto` with OpenSSL 3.5 or later. For the server only. |
| `@zamanapp/tashfir/web` | `WebCryptoProvider`: `@noble/post-quantum`, `@noble/curves` and WebCrypto. For the browser and the Electron renderer. `IndexedDbDeviceKeyHolder`: the device key holder of the browser, with a non-extractable WebCrypto wrapping key in IndexedDB. |
| `@zamanapp/tashfir/testing` | The same operations with injected randomness, for the test vectors only. Never import it in app code. |

Never use the Node provider in Electron: the BoringSSL of Electron has no post-quantum algorithms.

## Use

```ts
import { generateSymmetricKey, openValue, sealValue } from '@zamanapp/tashfir'
import { NodeCryptoProvider } from '@zamanapp/tashfir/node'

const provider = new NodeCryptoProvider()
const itemKey = generateSymmetricKey(provider)
const context = { purpose: 'field', table: 'emails', blob: 'header', rowId: email.id } as const

const header = await sealValue(provider, itemKey, { subject, from, to }, context)
const opened = await openValue(provider, itemKey, header, context)
```

The context goes into the associated data. A ciphertext opens only in its own blob of its own row.

## Formats (suite `0x01`)

| Format | Layout | Size |
| ------ | ------ | ---- |
| Envelope | version (1) ‖ suite ID (1) ‖ key UUID (16) ‖ nonce (12) ‖ ciphertext ‖ tag (16). Plaintext: CBOR, then `0x80` and zero bytes (ISO/IEC 7816-4). | 46 B + the plaintext + 1 |
| Symmetric key wrap | An envelope of the 32-byte key. The associated data binds the UUID of the wrapped key. | 79 B |
| Public-key wrap | version (1) ‖ suite ID (1) ‖ recipient key UUID (16) ‖ X-Wing ciphertext (1120) ‖ ciphertext ‖ tag. HPKE base mode (RFC 9180), KEM `0x647a`, HKDF-SHA-256, AES-256-GCM. | 1187 B |
| Signature | Composite ML-DSA-65 + Ed25519, `id-MLDSA65-Ed25519-SHA512` of RFC 10073 | 3373 B |
| File | version (1) ‖ suite ID (1) ‖ file key UUID (16) ‖ nonce prefix (7), then 64 KiB segments, each with a 16-byte tag. Segment nonce: prefix ‖ counter (4) ‖ last flag (1). | +41 B, +16 B for each segment |
| Storage key | BLAKE3 of the encrypted file, in hex | 64 characters |
| Registry entry | Deterministic CBOR map with integer keys: 0 format version, 1 account UUID, 2 sequence, 3 previous hash, 4 kind (`publish`, `revoke`, `reset`), 5 key UUID, 6 purpose (`signing`, `encryption`), 7 algorithm, 8 public key, 9 revocation reason, 10 signer key UUID. Hash: SHA-256(`tashfir-registry-entry-hash-v1` ‖ bytes). Signed by a signing key with the context `tashfir-registry-entry-v1`. `appendRegistryEntry` checks the chain rules. | About 2 KB for a signing key |
| Account keys | `createAccountKeys`: the account key, a signing key pair, an X-Wing key pair, each secret key sealed under the account key (key-wrap context, the pair UUID), and the first two registry entries (the signing key signs itself, then the X-Wing key). | About 6 KB |
| Password unlock wrap | A symmetric key wrap of the account key under HKDF-SHA-256(salt empty, the OPAQUE export key, `tashfir-password-unlock-v1`). The envelope header names the UUID of the unlock key, so the export key opens it. | 79 B |
| Recovery key | 32 random bytes. Words: 24 English BIP-39 words. Code: Crockford base32 of the key ‖ the first 3 bytes of its SHA-256, 56 characters in groups of 4. QR: `zaman-recovery:1:` ‖ the code without dashes. Unlock key: HKDF-SHA-256(`tashfir-recovery-unlock-v1`). Proof for the server: HKDF-SHA-256(`tashfir-recovery-auth-v1`). | 24 words, 69 characters |

| Device key entry | The account key kept on a device between restarts: version (1) ‖ nonce (12) ‖ AES-256-GCM of the account key ‖ tag (16), under the wrapping key of the device. Associated data: `tashfir-device-key-v1` ‖ deterministic CBOR map 0 format version, 1 account UUID, 2 account key UUID, 3 expiry (milliseconds since the epoch, or null for none). Each runtime keeps the wrapping key in its own safe place (WebCrypto non-extractable key, Keychain, Android Keystore, Electron `safeStorage`) behind `DeviceKeyHolder`. | 61 B |

X-Wing follows `draft-connolly-cfrg-xwing-kem-11`. A new draft version is a new suite ID, never a change of suite `0x01`.

## Test vectors

`vectors/` holds the vectors that define the suites.

| Folder | Contents |
| ------ | -------- |
| `vectors/external/` | X-Wing draft-11 (Appendix C), RFC 10073 (`id-MLDSA65-Ed25519-SHA512`), draft-ietf-hpke-pq-05 (KEM `0x647a`), RFC 9180 (key schedule and AES-256-GCM), RFC 5869 |
| `vectors/known-answer/` | Our formats with fixed inputs and fixed randomness, one file for each suite |

Each provider must give the same bytes for the known-answer vectors, or open them. Node `crypto` cannot take injected randomness for ML-KEM and ML-DSA, so on Node those vectors are opened and verified only. The cross-runtime tests seal on one runtime and open on the other.

The tests use Vitest with two projects: `node` runs both providers on Node, and `browser` runs the web provider in headless Chromium (Playwright).

```sh
pnpm test            # both projects
pnpm test:node       # Node only
pnpm test:browser    # headless Chromium only
pnpm vectors         # write the known-answer vectors again (see CONTRIBUTING.md first)
```

If Chromium is missing, install it once: `pnpm exec playwright install chromium`.

## Release gate

A release goes out only when all vectors pass on each runtime. CI runs them on Node and in headless Chromium, on Linux, macOS and Windows, and `prepublishOnly` runs them again before the publish. A change to a suite, or to a mobile provider, also needs a run on a real iPhone and a real Android phone. See [RELEASING.md](./RELEASING.md).

A suite becomes `current` in the registry only in a release where all runtimes passed.
