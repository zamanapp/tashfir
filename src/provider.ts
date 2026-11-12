/**
 * The primitives that each runtime gives. All the formats (envelope, HPKE, composite signatures,
 * STREAM) are written once over this interface, so that only the primitives differ by runtime.
 *
 * The optional `randomness` arguments exist only for known-answer test vectors. The public
 * functions of this package never pass them; only `@zamanapp/tashfir/testing` does.
 */
export interface CryptoProvider {
  readonly name: string

  /**
   * True when the provider accepts injected randomness for X-Wing encapsulation and ML-DSA
   * signing. Node `crypto` (OpenSSL) does not, so its known-answer tests only open and verify.
   */
  readonly acceptsInjectedRandomness: boolean

  /** Bytes from the random generator of the operating system. Never a seeded generator. */
  randomBytes(length: number): Uint8Array

  sha256(data: Uint8Array): Promise<Uint8Array>
  sha512(data: Uint8Array): Promise<Uint8Array>
  hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array>

  /** Returns the ciphertext followed by the 16-byte tag. */
  aes256GcmSeal(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array
  ): Promise<Uint8Array>

  /** Throws when the tag does not match. */
  aes256GcmOpen(
    key: Uint8Array,
    nonce: Uint8Array,
    sealed: Uint8Array,
    associatedData: Uint8Array
  ): Promise<Uint8Array>

  /** X-Wing (draft-connolly-cfrg-xwing-kem-11). The secret key is the 32-byte seed. */
  xWingPublicKey(secretKey: Uint8Array): Promise<Uint8Array>
  /** `randomness` is the 64-byte `eseed` of the draft. */
  xWingEncapsulate(
    publicKey: Uint8Array,
    randomness?: Uint8Array
  ): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }>
  xWingDecapsulate(ciphertext: Uint8Array, secretKey: Uint8Array): Promise<Uint8Array>

  /** ML-DSA-65 (FIPS 204). The secret key is the 32-byte seed. */
  mlDsa65PublicKey(seed: Uint8Array): Promise<Uint8Array>
  /** `randomness` is the 32-byte `rnd` of FIPS 204. Without it, signing is hedged. */
  mlDsa65Sign(
    seed: Uint8Array,
    message: Uint8Array,
    context: Uint8Array,
    randomness?: Uint8Array
  ): Promise<Uint8Array>
  mlDsa65Verify(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array,
    context: Uint8Array
  ): Promise<boolean>

  /** Ed25519 (RFC 8032). The secret key is the 32-byte seed. */
  ed25519PublicKey(secretKey: Uint8Array): Promise<Uint8Array>
  ed25519Sign(secretKey: Uint8Array, message: Uint8Array): Promise<Uint8Array>
  ed25519Verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>
}

export const X_WING_SECRET_KEY_LENGTH = 32
export const X_WING_PUBLIC_KEY_LENGTH = 1216
export const X_WING_CIPHERTEXT_LENGTH = 1120
export const X_WING_ENCAPSULATION_RANDOMNESS_LENGTH = 64
export const ML_DSA_65_SEED_LENGTH = 32
export const ML_DSA_65_PUBLIC_KEY_LENGTH = 1952
export const ML_DSA_65_SIGNATURE_LENGTH = 3309
export const ED25519_SECRET_KEY_LENGTH = 32
export const ED25519_PUBLIC_KEY_LENGTH = 32
export const ED25519_SIGNATURE_LENGTH = 64
