import crypto, { type KeyObject } from 'node:crypto'
import { concatBytes, expectLength, fromHex } from '../bytes.ts'
import { CryptoError } from '../errors.ts'
import {
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_SECRET_KEY_LENGTH,
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SEED_LENGTH,
  X_WING_CIPHERTEXT_LENGTH,
  X_WING_PUBLIC_KEY_LENGTH,
  X_WING_SECRET_KEY_LENGTH,
  type CryptoProvider,
} from '../provider.ts'

const X_WING_LABEL = fromHex('5c2e2f2f5e5c')
const ML_KEM_768_PUBLIC_KEY_LENGTH = 1184
const ML_KEM_768_CIPHERTEXT_LENGTH = 1088

type KeyType = 'ml-kem-768' | 'ml-dsa-65' | 'x25519' | 'ed25519'

/** A copy as a plain Uint8Array, so that callers never get a view of the Buffer pool. */
function plain(buffer: Uint8Array): Uint8Array {
  return new Uint8Array(buffer)
}

/**
 * Imports a raw secret key. ML-KEM and ML-DSA take the seed (`d ‖ z` of FIPS 203, `ξ` of
 * FIPS 204); the curves take the 32-byte secret key of RFC 7748 and RFC 8032.
 */
function privateKey(keyType: KeyType, raw: Uint8Array): KeyObject {
  const format = keyType === 'ml-kem-768' || keyType === 'ml-dsa-65' ? 'raw-seed' : 'raw-private'
  return crypto.createPrivateKey({ key: Buffer.from(raw), format, asymmetricKeyType: keyType })
}

function publicKey(keyType: KeyType, raw: Uint8Array): KeyObject {
  return crypto.createPublicKey({
    key: Buffer.from(raw),
    format: 'raw-public',
    asymmetricKeyType: keyType,
  })
}

function rawPublicKey(key: KeyObject): Uint8Array {
  const publicKeyObject = key.type === 'public' ? key : crypto.createPublicKey(key)
  return plain(publicKeyObject.export({ format: 'raw-public' }))
}

/**
 * X-Wing (draft-connolly-cfrg-xwing-kem-11) from the OpenSSL parts: the 32-byte seed expands with
 * SHAKE256 to the ML-KEM-768 seed (d ‖ z) and the X25519 secret key.
 */
function xWingKeys(secretKey: Uint8Array) {
  expectLength(secretKey, X_WING_SECRET_KEY_LENGTH, 'An X-Wing secret key')
  const expanded = crypto.createHash('shake256', { outputLength: 96 }).update(secretKey).digest()
  const mlKem = privateKey('ml-kem-768', expanded.subarray(0, 64))
  const x25519 = privateKey('x25519', expanded.subarray(64, 96))
  return { mlKem, x25519, x25519Public: rawPublicKey(x25519) }
}

function xWingCombiner(
  mlKemSharedSecret: Uint8Array,
  x25519SharedSecret: Uint8Array,
  x25519Ciphertext: Uint8Array,
  x25519PublicKey: Uint8Array
): Uint8Array {
  return plain(
    crypto
      .createHash('sha3-256')
      .update(
        concatBytes(
          mlKemSharedSecret,
          x25519SharedSecret,
          x25519Ciphertext,
          x25519PublicKey,
          X_WING_LABEL
        )
      )
      .digest()
  )
}

/**
 * The provider for Node (the server). It uses only Node `crypto` with OpenSSL 3.5 or later. Never
 * use it in Electron: the BoringSSL of Electron has no post-quantum algorithms.
 */
export class NodeCryptoProvider implements CryptoProvider {
  readonly name = 'node'
  readonly acceptsInjectedRandomness = false

  randomBytes(length: number): Uint8Array {
    return plain(crypto.randomBytes(length))
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return plain(crypto.createHash('sha256').update(data).digest())
  }

  async sha512(data: Uint8Array): Promise<Uint8Array> {
    return plain(crypto.createHash('sha512').update(data).digest())
  }

  async hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    return plain(crypto.createHmac('sha256', key).update(data).digest())
  }

  async aes256GcmSeal(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array
  ): Promise<Uint8Array> {
    const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 })
    cipher.setAAD(associatedData)
    return concatBytes(cipher.update(plaintext), cipher.final(), cipher.getAuthTag())
  }

  async aes256GcmOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    sealed: Uint8Array,
    associatedData: Uint8Array
  ): Promise<Uint8Array> {
    if (sealed.length < 16) throw new CryptoError('E_MALFORMED', 'The ciphertext has no tag')
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: 16 })
    decipher.setAAD(associatedData)
    decipher.setAuthTag(sealed.subarray(sealed.length - 16))
    return concatBytes(decipher.update(sealed.subarray(0, sealed.length - 16)), decipher.final())
  }

  async xWingPublicKey(secretKey: Uint8Array): Promise<Uint8Array> {
    const keys = xWingKeys(secretKey)
    return concatBytes(rawPublicKey(keys.mlKem), keys.x25519Public)
  }

  async xWingEncapsulate(
    recipientPublicKey: Uint8Array,
    randomness?: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
    if (randomness) {
      throw new CryptoError('E_UNSUPPORTED', 'Node crypto cannot take injected ML-KEM randomness')
    }
    expectLength(recipientPublicKey, X_WING_PUBLIC_KEY_LENGTH, 'An X-Wing public key')
    const mlKemPublic = recipientPublicKey.subarray(0, ML_KEM_768_PUBLIC_KEY_LENGTH)
    const x25519Public = recipientPublicKey.subarray(ML_KEM_768_PUBLIC_KEY_LENGTH)
    const ephemeral = crypto.generateKeyPairSync('x25519')
    const x25519Ciphertext = rawPublicKey(ephemeral.publicKey)
    const x25519SharedSecret = crypto.diffieHellman({
      privateKey: ephemeral.privateKey,
      publicKey: publicKey('x25519', x25519Public),
    })
    // The SPKI import checks the encapsulation key as FIPS 203 §7.2 asks.
    const mlKem = crypto.encapsulate(publicKey('ml-kem-768', mlKemPublic))
    return {
      ciphertext: concatBytes(mlKem.ciphertext, x25519Ciphertext),
      sharedSecret: xWingCombiner(
        mlKem.sharedKey,
        x25519SharedSecret,
        x25519Ciphertext,
        x25519Public
      ),
    }
  }

  async xWingDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array> {
    expectLength(ciphertext, X_WING_CIPHERTEXT_LENGTH, 'An X-Wing ciphertext')
    const keys = xWingKeys(secretKey)
    const x25519Ciphertext = ciphertext.subarray(ML_KEM_768_CIPHERTEXT_LENGTH)
    const mlKemSharedSecret = crypto.decapsulate(
      keys.mlKem,
      ciphertext.subarray(0, ML_KEM_768_CIPHERTEXT_LENGTH)
    )
    const x25519SharedSecret = crypto.diffieHellman({
      privateKey: keys.x25519,
      publicKey: publicKey('x25519', x25519Ciphertext),
    })
    return xWingCombiner(mlKemSharedSecret, x25519SharedSecret, x25519Ciphertext, keys.x25519Public)
  }

  async mlDsa65PublicKey(seed: Uint8Array): Promise<Uint8Array> {
    expectLength(seed, ML_DSA_65_SEED_LENGTH, 'An ML-DSA-65 seed')
    return rawPublicKey(privateKey('ml-dsa-65', seed))
  }

  async mlDsa65Sign(
    seed: Uint8Array,
    message: Uint8Array,
    context: Uint8Array,
    randomness?: Uint8Array
  ): Promise<Uint8Array> {
    if (randomness) {
      throw new CryptoError('E_UNSUPPORTED', 'Node crypto cannot take injected ML-DSA randomness')
    }
    expectLength(seed, ML_DSA_65_SEED_LENGTH, 'An ML-DSA-65 seed')
    return plain(crypto.sign(null, message, { key: privateKey('ml-dsa-65', seed), context }))
  }

  async mlDsa65Verify(
    key: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context: Uint8Array
  ): Promise<boolean> {
    if (key.length !== ML_DSA_65_PUBLIC_KEY_LENGTH) return false
    try {
      return crypto.verify(null, message, { key: publicKey('ml-dsa-65', key), context }, signature)
    } catch {
      return false
    }
  }

  async ed25519PublicKey(secretKey: Uint8Array): Promise<Uint8Array> {
    expectLength(secretKey, ED25519_SECRET_KEY_LENGTH, 'An Ed25519 secret key')
    return rawPublicKey(privateKey('ed25519', secretKey))
  }

  async ed25519Sign(secretKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    expectLength(secretKey, ED25519_SECRET_KEY_LENGTH, 'An Ed25519 secret key')
    return plain(crypto.sign(null, message, privateKey('ed25519', secretKey)))
  }

  async ed25519Verify(
    key: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): Promise<boolean> {
    if (key.length !== ED25519_PUBLIC_KEY_LENGTH) return false
    try {
      return crypto.verify(null, message, publicKey('ed25519', key), signature)
    } catch {
      return false
    }
  }
}
