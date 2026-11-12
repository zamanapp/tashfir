import { fromHex } from '../src/bytes.ts'

export const hex = fromHex

export function base64(value: string): Uint8Array {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0))
}

/** A plaintext that both the generator and the tests can rebuild from its length. */
export function patternBytes(length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => index % 251)
}

/** Fixed test input: `length` bytes that start with `first` and count up. */
export function fixedBytes(length: number, first: number): Uint8Array {
  return Uint8Array.from({ length }, (_, index) => (first + index) % 256)
}

/** The code of the CryptoError that `action` throws, or undefined. */
export function errorCode(action: () => unknown): string | undefined {
  try {
    action()
  } catch (error) {
    return (error as { code?: string }).code
  }
  return undefined
}
