export type CryptoErrorCode =
  | 'E_UNKNOWN_VERSION'
  | 'E_UNKNOWN_SUITE'
  | 'E_SUITE_RETIRED'
  | 'E_KEY_MISMATCH'
  | 'E_DECRYPT_FAILED'
  | 'E_MALFORMED'
  | 'E_INVALID_INPUT'
  | 'E_UNSUPPORTED'
  | 'E_REGISTRY_REJECTED'

/**
 * Every failure of this package. The message never holds key bytes or plaintext, so a caller
 * can log it.
 */
export class CryptoError extends Error {
  readonly code: CryptoErrorCode

  constructor(code: CryptoErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'CryptoError'
    this.code = code
  }
}
