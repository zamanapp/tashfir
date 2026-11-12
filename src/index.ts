export { CryptoError, type CryptoErrorCode } from './errors.ts'
export type { CryptoProvider } from './provider.ts'
export {
  currentSuite,
  suiteForReading,
  ENVELOPE_VERSION,
  SIGNATURE_ALGORITHMS,
  type Suite,
  type SuiteState,
  type SignatureAlgorithm,
} from './suites.ts'
export { bytesToUuid, uuidToBytes, toHex, fromHex, equalBytes } from './bytes.ts'
export { encodeCbor, decodeCbor } from './cbor.ts'
export type { EnvelopeContext } from './context.ts'
export {
  generateSymmetricKey,
  readEnvelopeHeader,
  sealBytes,
  openBytes,
  sealValue,
  openValue,
  wrapKey,
  unwrapKey,
  HEADER_LENGTH,
  type SymmetricKey,
  type EnvelopeHeader,
} from './envelope.ts'
export {
  generateKemKeyPair,
  readPublicKeyWrapHeader,
  wrapKeyToPublicKey,
  unwrapKeyWithSecretKey,
  type KemKeyPair,
  type PublicKeyWrapHeader,
} from './hpke.ts'
export {
  generateSigningKeyPair,
  signingPublicKey,
  sign,
  verify,
  SIGNATURE_LENGTH,
  SIGNING_PUBLIC_KEY_LENGTH,
  SIGNING_SECRET_KEY_LENGTH,
  type SigningKeyPair,
} from './signature.ts'
export {
  encryptFile,
  decryptFile,
  openFileSegment,
  readFileHeader,
  segmentByteRange,
  encryptedFileLength,
  FILE_HEADER_LENGTH,
  type FileHeader,
} from './stream.ts'
export { hkdf } from './hkdf.ts'
export { storageKey } from './storage_key.ts'
