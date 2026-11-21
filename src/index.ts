export { CryptoError, type CryptoErrorCode } from './errors.ts'
export type { CryptoProvider } from './provider.ts'
export {
  currentSuite,
  suiteForReading,
  ENVELOPE_VERSION,
  SIGNATURE_ALGORITHMS,
  KEM_ALGORITHMS,
  type KemAlgorithm,
  type Suite,
  type SuiteState,
  type SignatureAlgorithm,
} from './suites.ts'
export { bytesToUuid, uuidToBytes, newKeyId, toHex, fromHex, equalBytes } from './bytes.ts'
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
export {
  REGISTRY_FORMAT_VERSION,
  REGISTRY_HASH_LENGTH,
  encodeRegistryEntry,
  decodeRegistryEntry,
  registryEntryHash,
  signRegistryEntry,
  verifyRegistryEntrySignature,
  emptyRegistryChain,
  appendRegistryEntry,
  replayRegistryChain,
  publicKeyLengthOf,
  type RegistryEntry,
  type RegistryEntryKind,
  type RegistryKeyPurpose,
  type RevocationReason,
  type RegistryKey,
  type RegistryChain,
  type SignedRegistryEntry,
} from './registry.ts'
export {
  createAccountKeys,
  createResetKeys,
  passwordUnlockKey,
  wrapAccountKeyForPassword,
  openAccountKeyWithPassword,
  wrapSecretKey,
  openSecretKey,
  type AccountKeys,
  type AccountKeyBundle,
  type AccountKeyPair,
  type RegistryChainHead,
} from './account_keys.ts'
export {
  RECOVERY_KEY_LENGTH,
  generateRecoveryKey,
  recoveryKeyToWords,
  recoveryKeyFromWords,
  recoveryKeyToCode,
  recoveryKeyFromCode,
  recoveryQrPayload,
  recoveryKeyFromQrPayload,
  recoveryProof,
  createRecoveryKit,
  openAccountKeyWithRecoveryKey,
  openRecoveryKeyCopy,
  type RecoveryKit,
} from './recovery.ts'
export {
  DEVICE_KEY_FORMAT_VERSION,
  rawDeviceWrappingKey,
  deviceKeyAssociatedData,
  openDeviceKeyEntry,
  keepAccountKeyOnDevice,
  openAccountKeyOnDevice,
  forgetAccountKeyOnDevice,
  keepOnlyAccountOnDevice,
  type DeviceKeyEntry,
  type DeviceKeyHolder,
  type DeviceWrappingKey,
} from './device_keys.ts'
export { hkdf } from './hkdf.ts'
export { storageKey } from './storage_key.ts'
