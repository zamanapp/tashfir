import { bytesToUuid, concatBytes, expectLength, uint32, uuidToBytes } from './bytes.ts'
import { SYMMETRIC_KEY_LENGTH, TAG_LENGTH, type SymmetricKey } from './envelope.ts'
import { CryptoError } from './errors.ts'
import type { CryptoProvider } from './provider.ts'
import { currentSuite, ENVELOPE_VERSION, suiteForReading } from './suites.ts'

/**
 * Stored files use the STREAM construction, as `age` does:
 * fixed-size segments, each sealed with AES-256-GCM. A reader can stream, read a range, and stops
 * at the first changed segment. A cut file fails, because only the last segment has the last
 * flag.
 *
 * File: version (1) ‖ suite ID (1) ‖ file key UUID (16) ‖ nonce prefix (7), then the segments.
 * Segment nonce: nonce prefix (7) ‖ segment counter (4) ‖ last flag (1).
 * The associated data of each segment is the file header.
 */
export const FILE_HEADER_LENGTH = 25
const NONCE_PREFIX_LENGTH = 7
const MAX_SEGMENTS = 2 ** 32

export interface FileHeader {
  version: number
  suiteId: number
  keyId: string
  noncePrefix: Uint8Array
}

function segmentNonce(noncePrefix: Uint8Array, index: number, last: boolean): Uint8Array {
  return concatBytes(noncePrefix, uint32(index), Uint8Array.of(last ? 1 : 0))
}

/** Reads the first 25 bytes of a file, for example from a ranged read of storage. */
export function readFileHeader(file: Uint8Array): FileHeader {
  if (file.length < FILE_HEADER_LENGTH) {
    throw new CryptoError('E_MALFORMED', 'The encrypted file is too short')
  }
  if (file[0] !== ENVELOPE_VERSION) {
    throw new CryptoError('E_UNKNOWN_VERSION', `Unknown file version ${file[0]}`)
  }
  return {
    version: file[0],
    suiteId: file[1],
    keyId: bytesToUuid(file.subarray(2, 18)),
    noncePrefix: file.subarray(18, FILE_HEADER_LENGTH),
  }
}

/** The size of the encrypted file for a plaintext of `plaintextLength` bytes. */
export function encryptedFileLength(plaintextLength: number): number {
  const segmentSize = currentSuite().fileSegmentSize
  const segmentCount = Math.max(1, Math.ceil(plaintextLength / segmentSize))
  return FILE_HEADER_LENGTH + plaintextLength + segmentCount * TAG_LENGTH
}

/**
 * The byte range of one sealed segment in the encrypted file, for a ranged read from storage.
 * The end is exclusive.
 */
export function segmentByteRange(
  segmentIndex: number,
  encryptedLength: number,
  suiteId = currentSuite().id
): { start: number; end: number; last: boolean } {
  const sealedSegmentSize = suiteForReading(suiteId).fileSegmentSize + TAG_LENGTH
  const start = FILE_HEADER_LENGTH + segmentIndex * sealedSegmentSize
  if (!Number.isInteger(segmentIndex) || segmentIndex < 0 || start >= encryptedLength) {
    throw new CryptoError('E_INVALID_INPUT', `The file has no segment ${segmentIndex}`)
  }
  const end = Math.min(start + sealedSegmentSize, encryptedLength)
  return { start, end, last: end === encryptedLength }
}

/** The encryption with its nonce prefix as an argument. Only the known-answer tests pass it. */
export async function encryptFileWith(
  provider: CryptoProvider,
  key: SymmetricKey,
  plaintext: Uint8Array,
  options: { noncePrefix?: Uint8Array } = {}
): Promise<Uint8Array> {
  expectLength(key.bytes, SYMMETRIC_KEY_LENGTH, 'A file key')
  const suite = currentSuite()
  const noncePrefix = options.noncePrefix ?? provider.randomBytes(NONCE_PREFIX_LENGTH)
  expectLength(noncePrefix, NONCE_PREFIX_LENGTH, 'The nonce prefix')
  const header = concatBytes(
    Uint8Array.of(ENVELOPE_VERSION, suite.id),
    uuidToBytes(key.id),
    noncePrefix
  )
  // An empty file is one empty last segment. Otherwise a full last segment is the last one; no
  // empty segment follows it.
  const segmentCount = Math.max(1, Math.ceil(plaintext.length / suite.fileSegmentSize))
  if (segmentCount > MAX_SEGMENTS) throw new CryptoError('E_INVALID_INPUT', 'The file is too large')
  const output = new Uint8Array(encryptedFileLength(plaintext.length))
  output.set(header)
  let offset = FILE_HEADER_LENGTH
  for (let index = 0; index < segmentCount; index++) {
    const segment = plaintext.subarray(
      index * suite.fileSegmentSize,
      (index + 1) * suite.fileSegmentSize
    )
    const sealed = await provider.aes256GcmSeal(
      key.bytes,
      segmentNonce(noncePrefix, index, index === segmentCount - 1),
      segment,
      header
    )
    output.set(sealed, offset)
    offset += sealed.length
  }
  return output
}

/** Encrypts a whole file under its own file key. */
export async function encryptFile(
  provider: CryptoProvider,
  key: SymmetricKey,
  plaintext: Uint8Array
): Promise<Uint8Array> {
  return encryptFileWith(provider, key, plaintext)
}

/** Opens one segment that a ranged read returned. `header` is the first 25 bytes of the file. */
export async function openFileSegment(
  provider: CryptoProvider,
  key: SymmetricKey,
  header: Uint8Array,
  segmentIndex: number,
  sealedSegment: Uint8Array,
  last: boolean
): Promise<Uint8Array> {
  const fileHeader = readFileHeader(header)
  const suite = suiteForReading(fileHeader.suiteId)
  if (fileHeader.keyId !== key.id) {
    throw new CryptoError('E_KEY_MISMATCH', `The file is encrypted with key ${fileHeader.keyId}`)
  }
  if (
    sealedSegment.length < TAG_LENGTH ||
    sealedSegment.length > suite.fileSegmentSize + TAG_LENGTH
  ) {
    throw new CryptoError('E_MALFORMED', 'The segment has a wrong size')
  }
  if (!last && sealedSegment.length !== suite.fileSegmentSize + TAG_LENGTH) {
    throw new CryptoError('E_MALFORMED', 'Only the last segment can be short')
  }
  // An empty last segment is valid only as the whole of an empty file.
  if (last && segmentIndex > 0 && sealedSegment.length === TAG_LENGTH) {
    throw new CryptoError('E_MALFORMED', 'The last segment is empty')
  }
  try {
    return await provider.aes256GcmOpen(
      key.bytes,
      segmentNonce(fileHeader.noncePrefix, segmentIndex, last),
      sealedSegment,
      header.subarray(0, FILE_HEADER_LENGTH)
    )
  } catch (error) {
    throw new CryptoError('E_DECRYPT_FAILED', `Segment ${segmentIndex} does not open`, {
      cause: error,
    })
  }
}

export async function decryptFile(
  provider: CryptoProvider,
  key: SymmetricKey,
  file: Uint8Array
): Promise<Uint8Array> {
  const { suiteId } = readFileHeader(file)
  if (file.length < FILE_HEADER_LENGTH + TAG_LENGTH) {
    throw new CryptoError('E_MALFORMED', 'The encrypted file has no segment')
  }
  const segments: Uint8Array[] = []
  for (let index = 0; ; index++) {
    const range = segmentByteRange(index, file.length, suiteId)
    segments.push(
      await openFileSegment(
        provider,
        key,
        file,
        index,
        file.subarray(range.start, range.end),
        range.last
      )
    )
    if (range.last) break
  }
  return concatBytes(...segments)
}
