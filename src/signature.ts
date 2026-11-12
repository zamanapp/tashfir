import { concatBytes, expectLength, utf8 } from './bytes.ts'
import { CryptoError } from './errors.ts'
import {
  ED25519_PUBLIC_KEY_LENGTH,
  ED25519_SECRET_KEY_LENGTH,
  ED25519_SIGNATURE_LENGTH,
  ML_DSA_65_PUBLIC_KEY_LENGTH,
  ML_DSA_65_SEED_LENGTH,
  ML_DSA_65_SIGNATURE_LENGTH,
  type CryptoProvider,
} from './provider.ts'

/**
 * Composite ML-DSA-65 + Ed25519, `id-MLDSA65-Ed25519-SHA512` of RFC 10073, byte for byte.
 * A signature is valid only if both parts are valid.
 */
const PREFIX = utf8('CompositeAlgorithmSignatures2025')
const LABEL = utf8('COMPSIG-MLDSA65-Ed25519-SHA512')

/** mldsaSeed (32) ‖ Ed25519 secret key (32) */
export const SIGNING_SECRET_KEY_LENGTH = ML_DSA_65_SEED_LENGTH + ED25519_SECRET_KEY_LENGTH
/** mldsaPK (1952) ‖ Ed25519 public key (32) */
export const SIGNING_PUBLIC_KEY_LENGTH = ML_DSA_65_PUBLIC_KEY_LENGTH + ED25519_PUBLIC_KEY_LENGTH
/** mldsaSig (3309) ‖ Ed25519 signature (64) */
export const SIGNATURE_LENGTH = ML_DSA_65_SIGNATURE_LENGTH + ED25519_SIGNATURE_LENGTH

export interface SigningKeyPair {
  publicKey: Uint8Array
  secretKey: Uint8Array
}

/** M' = Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(M) (RFC 10073 §2.2). */
async function representative(
  provider: CryptoProvider,
  message: Uint8Array,
  context: Uint8Array
): Promise<Uint8Array> {
  if (context.length > 255) {
    throw new CryptoError('E_INVALID_INPUT', 'The signature context is longer than 255 bytes')
  }
  return concatBytes(
    PREFIX,
    LABEL,
    Uint8Array.of(context.length),
    context,
    await provider.sha512(message)
  )
}

export async function signingPublicKey(
  provider: CryptoProvider,
  secretKey: Uint8Array
): Promise<Uint8Array> {
  expectLength(secretKey, SIGNING_SECRET_KEY_LENGTH, 'A signing secret key')
  return concatBytes(
    await provider.mlDsa65PublicKey(secretKey.subarray(0, ML_DSA_65_SEED_LENGTH)),
    await provider.ed25519PublicKey(secretKey.subarray(ML_DSA_65_SEED_LENGTH))
  )
}

export async function generateSigningKeyPair(provider: CryptoProvider): Promise<SigningKeyPair> {
  const secretKey = provider.randomBytes(SIGNING_SECRET_KEY_LENGTH)
  return { secretKey, publicKey: await signingPublicKey(provider, secretKey) }
}

/**
 * The signature with the ML-DSA randomness (`rnd`, 32 bytes) as an argument. Only the
 * known-answer tests pass it; `sign` uses hedged signing.
 */
export async function signWith(
  provider: CryptoProvider,
  secretKey: Uint8Array,
  message: Uint8Array,
  context: Uint8Array,
  options: { randomness?: Uint8Array } = {}
): Promise<Uint8Array> {
  expectLength(secretKey, SIGNING_SECRET_KEY_LENGTH, 'A signing secret key')
  const messageRepresentative = await representative(provider, message, context)
  return concatBytes(
    await provider.mlDsa65Sign(
      secretKey.subarray(0, ML_DSA_65_SEED_LENGTH),
      messageRepresentative,
      LABEL,
      options.randomness
    ),
    await provider.ed25519Sign(secretKey.subarray(ML_DSA_65_SEED_LENGTH), messageRepresentative)
  )
}

/**
 * Signs a message. `context` names what is signed (for example an invitation or a registry
 * entry), so that a signature of one kind is never valid as another kind.
 */
export async function sign(
  provider: CryptoProvider,
  secretKey: Uint8Array,
  message: Uint8Array,
  context: Uint8Array
): Promise<Uint8Array> {
  return signWith(provider, secretKey, message, context)
}

export async function verify(
  provider: CryptoProvider,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  context: Uint8Array
): Promise<boolean> {
  if (publicKey.length !== SIGNING_PUBLIC_KEY_LENGTH || signature.length !== SIGNATURE_LENGTH) {
    return false
  }
  const messageRepresentative = await representative(provider, message, context)
  // Both checks always run. The result is the AND of the two.
  const [mlDsaValid, ed25519Valid] = await Promise.all([
    provider.mlDsa65Verify(
      publicKey.subarray(0, ML_DSA_65_PUBLIC_KEY_LENGTH),
      messageRepresentative,
      signature.subarray(0, ML_DSA_65_SIGNATURE_LENGTH),
      LABEL
    ),
    provider.ed25519Verify(
      publicKey.subarray(ML_DSA_65_PUBLIC_KEY_LENGTH),
      messageRepresentative,
      signature.subarray(ML_DSA_65_SIGNATURE_LENGTH)
    ),
  ])
  return mlDsaValid && ed25519Valid
}
