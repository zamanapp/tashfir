import { concatBytes, uint16, utf8, uuidToBytes } from './bytes.ts'
import { CryptoError } from './errors.ts'

/**
 * What a ciphertext belongs to. It goes into the associated data, so a ciphertext opens only in
 * its own place: a server cannot move the body of one email to another row, or use a key wrap as
 * a field.
 */
export type EnvelopeContext =
  /** A blob of encrypted fields of one row. */
  | { purpose: 'field'; table: string; blob: string; rowId: string }
  /** A key (`wrappedKeyId`) wrapped under another key or to a public key. */
  | { purpose: 'key-wrap'; wrappedKeyId: string }

/**
 * Each part has a 2-byte length prefix, so that two different contexts never give the same bytes
 * ("ab" + "c" and "a" + "bc" differ).
 */
export function encodeParts(parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts.flatMap((part) => [uint16(part.length), part]))
}

export function encodeContext(context: EnvelopeContext): Uint8Array {
  switch (context.purpose) {
    case 'field': {
      if (!context.table || !context.blob) {
        throw new CryptoError('E_INVALID_INPUT', 'A field context needs a table and a blob name')
      }
      return encodeParts([
        utf8('field'),
        utf8(context.table),
        utf8(context.blob),
        uuidToBytes(context.rowId),
      ])
    }
    case 'key-wrap':
      return encodeParts([utf8('key-wrap'), uuidToBytes(context.wrappedKeyId)])
  }
}
