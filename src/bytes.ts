import {
  parse as parseUuid,
  stringify as stringifyUuid,
  v7 as uuidV7,
  validate as validateUuid,
} from 'uuid'
import { CryptoError } from './errors.ts'

const textEncoder = new TextEncoder()

export function utf8(text: string): Uint8Array {
  return textEncoder.encode(text)
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((length, part) => length + part.length, 0)
  const result = new Uint8Array(total)
  let offset = 0
  for (const part of parts) {
    result.set(part, offset)
    offset += part.length
  }
  return result
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  // No early exit, so the time does not show where two values differ.
  let difference = 0
  for (let index = 0; index < left.length; index++) difference |= left[index] ^ right[index]
  return difference === 0
}

export function uint16(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new CryptoError('E_INVALID_INPUT', `Value ${value} does not fit in 2 bytes`)
  }
  return Uint8Array.of(value >>> 8, value & 0xff)
}

export function uint32(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new CryptoError('E_INVALID_INPUT', `Value ${value} does not fit in 4 bytes`)
  }
  return Uint8Array.of(value >>> 24, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff)
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new CryptoError('E_INVALID_INPUT', 'Not a hex string')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}

export function uuidToBytes(uuid: string): Uint8Array {
  if (!validateUuid(uuid)) throw new CryptoError('E_INVALID_INPUT', 'Not a UUID')
  return parseUuid(uuid)
}

/** Reads a key UUID from a header. A changed header can hold bytes that are not a valid UUID. */
export function bytesToUuid(bytes: Uint8Array): string {
  if (bytes.length !== 16) throw new CryptoError('E_INVALID_INPUT', 'A UUID has 16 bytes')
  try {
    return stringifyUuid(bytes)
  } catch (error) {
    throw new CryptoError('E_MALFORMED', 'The header holds no valid key UUID', { cause: error })
  }
}

/**
 * A new key UUID: version 7 (RFC 9562), like the row IDs of the backend. The 16 random bytes come
 * from the provider, so the UUID does not depend on a global random generator, which NativeScript
 * does not have.
 */
export function newKeyId(random: Uint8Array): string {
  expectLength(random, 16, 'The random bytes of a UUID')
  return uuidV7({ random })
}

export function expectLength(bytes: Uint8Array, length: number, name: string): void {
  if (bytes.length !== length) {
    throw new CryptoError(
      'E_INVALID_INPUT',
      `${name} must have ${length} bytes, not ${bytes.length}`
    )
  }
}
