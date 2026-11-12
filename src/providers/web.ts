import { ed25519 } from '@noble/curves/ed25519.js'
import { ml_kem768_x25519 as xWing } from '@noble/post-quantum/hybrid.js'
import { ml_dsa65 as mlDsa65 } from '@noble/post-quantum/ml-dsa.js'
import { expectLength } from '../bytes.ts'
import { CryptoError } from '../errors.ts'
import {
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_SECRET_KEY_LENGTH,
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SEED_LENGTH,
  X_WING_CIPHERTEXT_LENGTH,
  X_WING_ENCAPSULATION_RANDOMNESS_LENGTH,
  X_WING_PUBLIC_KEY_LENGTH,
  X_WING_SECRET_KEY_LENGTH,
  type CryptoProvider,
} from '../provider.ts'

/** getRandomValues fills at most 65,536 bytes for each call. */
const RANDOM_CHUNK = 65_536
const HMAC_BLOCK_SIZE = 64

/**
 * WebCrypto types ask for an ArrayBuffer-backed view. Our bytes are always ArrayBuffer-backed;
 * the cast only narrows the type.
 */
function source(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes as Uint8Array<ArrayBuffer>
}

function subtle(): SubtleCrypto {
  const crypto = globalThis.crypto
  if (!crypto?.subtle) throw new CryptoError('E_UNSUPPORTED', 'WebCrypto is not available')
  return crypto.subtle
}

/**
 * The provider for the browser and the Electron renderer: `@noble/post-quantum` and
 * `@noble/curves` for X-Wing, ML-DSA-65 and Ed25519, and WebCrypto for AES-256-GCM, HMAC and the
 * hashes. `@noble/post-quantum` does not claim constant time; ML-DSA signing has loops that
 * depend on the secret.
 */
export class WebCryptoProvider implements CryptoProvider {
  readonly name = 'web'
  readonly acceptsInjectedRandomness = true

  randomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length)
    for (let offset = 0; offset < length; offset += RANDOM_CHUNK) {
      globalThis.crypto.getRandomValues(bytes.subarray(offset, offset + RANDOM_CHUNK))
    }
    return bytes
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await subtle().digest('SHA-256', source(data)))
  }

  async sha512(data: Uint8Array): Promise<Uint8Array> {
    return new Uint8Array(await subtle().digest('SHA-512', source(data)))
  }

  async hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    // WebCrypto refuses an empty HMAC key. HMAC pads the key with zeros to the block size, so a
    // block of zeros gives the same result as an empty key.
    const keyBytes = key.length === 0 ? new Uint8Array(HMAC_BLOCK_SIZE) : key
    const cryptoKey = await subtle().importKey(
      'raw',
      source(keyBytes),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    )
    return new Uint8Array(await subtle().sign('HMAC', cryptoKey, source(data)))
  }

  async aes256GcmSeal(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array
  ): Promise<Uint8Array> {
    const cryptoKey = await subtle().importKey('raw', source(key), 'AES-GCM', false, ['encrypt'])
    return new Uint8Array(
      await subtle().encrypt(
        {
          name: 'AES-GCM',
          iv: source(nonce),
          additionalData: source(associatedData),
          tagLength: 128,
        },
        cryptoKey,
        source(plaintext)
      )
    )
  }

  async aes256GcmOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    sealed: Uint8Array,
    associatedData: Uint8Array
  ): Promise<Uint8Array> {
    const cryptoKey = await subtle().importKey('raw', source(key), 'AES-GCM', false, ['decrypt'])
    return new Uint8Array(
      await subtle().decrypt(
        {
          name: 'AES-GCM',
          iv: source(nonce),
          additionalData: source(associatedData),
          tagLength: 128,
        },
        cryptoKey,
        source(sealed)
      )
    )
  }

  async xWingPublicKey(secretKey: Uint8Array): Promise<Uint8Array> {
    expectLength(secretKey, X_WING_SECRET_KEY_LENGTH, 'An X-Wing secret key')
    return xWing.getPublicKey(secretKey)
  }

  async xWingEncapsulate(
    publicKey: Uint8Array,
    randomness?: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
    expectLength(publicKey, X_WING_PUBLIC_KEY_LENGTH, 'An X-Wing public key')
    if (randomness)
      expectLength(randomness, X_WING_ENCAPSULATION_RANDOMNESS_LENGTH, 'The X-Wing eseed')
    const { cipherText, sharedSecret } = xWing.encapsulate(publicKey, randomness)
    return { ciphertext: cipherText, sharedSecret }
  }

  async xWingDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    expectLength(ciphertext, X_WING_CIPHERTEXT_LENGTH, 'An X-Wing ciphertext')
    expectLength(secretKey, X_WING_SECRET_KEY_LENGTH, 'An X-Wing secret key')
    return xWing.decapsulate(ciphertext, secretKey)
  }

  async mlDsa65PublicKey(seed: Uint8Array): Promise<Uint8Array> {
    expectLength(seed, ML_DSA_65_SEED_LENGTH, 'An ML-DSA-65 seed')
    return mlDsa65.keygen(seed).publicKey
  }

  async mlDsa65Sign(
    seed: Uint8Array,
    message: Uint8Array,
    context: Uint8Array,
    randomness?: Uint8Array
  ): Promise<Uint8Array> {
    expectLength(seed, ML_DSA_65_SEED_LENGTH, 'An ML-DSA-65 seed')
    // noble keeps the expanded secret key, so it is derived from the seed for each signature.
    const { secretKey } = mlDsa65.keygen(seed)
    return mlDsa65.sign(message, secretKey, { context, extraEntropy: randomness })
  }

  async mlDsa65Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context: Uint8Array
  ): Promise<boolean> {
    if (publicKey.length !== ML_DSA_65_PUBLIC_KEY_LENGTH) return false
    try {
      return mlDsa65.verify(signature, message, publicKey, { context })
    } catch {
      return false
    }
  }

  async ed25519PublicKey(secretKey: Uint8Array): Promise<Uint8Array> {
    expectLength(secretKey, ED25519_SECRET_KEY_LENGTH, 'An Ed25519 secret key')
    return ed25519.getPublicKey(secretKey)
  }

  async ed25519Sign(secretKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    expectLength(secretKey, ED25519_SECRET_KEY_LENGTH, 'An Ed25519 secret key')
    return ed25519.sign(message, secretKey)
  }

  async ed25519Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    if (publicKey.length !== ED25519_PUBLIC_KEY_LENGTH) return false
    try {
      // Strict RFC 8032 rules (no ZIP 215), the same rules as OpenSSL on the server, so that both
      // runtimes accept the same signatures.
      return ed25519.verify(signature, message, publicKey, { zip215: false })
    } catch {
      return false
    }
  }
}
