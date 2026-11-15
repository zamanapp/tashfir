import { describe, expect, test } from 'vitest'
import { createAccountKeys } from '../src/account_keys.ts'
import { equalBytes } from '../src/bytes.ts'
import {
  createRecoveryKit,
  openAccountKeyWithRecoveryKey,
  openRecoveryKeyCopy,
  recoveryKeyFromCode,
  recoveryKeyFromQrPayload,
  recoveryKeyFromWords,
  recoveryKeyToCode,
  recoveryKeyToWords,
  recoveryProof,
  recoveryQrPayload,
} from '../src/recovery.ts'
import { errorCode, fixedBytes } from './fixtures.ts'
import { providers } from './providers.ts'

async function errorCodeOf(action: () => Promise<unknown>): Promise<string | undefined> {
  try {
    await action()
  } catch (error) {
    return (error as { code?: string }).code
  }
  return undefined
}

const recoveryKey = fixedBytes(32, 0x10)

describe.each(providers)('recovery key ($name)', (provider) => {
  test('the words, the code and the QR payload give back the same key', async () => {
    const words = recoveryKeyToWords(recoveryKey)
    expect(words).toHaveLength(24)
    expect(equalBytes(recoveryKeyFromWords(words), recoveryKey)).toBe(true)
    expect(equalBytes(recoveryKeyFromWords(`  ${words.join('   ').toUpperCase()} `), recoveryKey)).toBe(true)

    const code = await recoveryKeyToCode(provider, recoveryKey)
    expect(code).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){13}[0-9A-HJKMNP-TV-Z]{4}$/)
    expect(equalBytes(await recoveryKeyFromCode(provider, code), recoveryKey)).toBe(true)
    expect(equalBytes(await recoveryKeyFromCode(provider, code.replace(/-/g, ' ').toLowerCase()), recoveryKey)).toBe(true)
    // Crockford base32 reads O as 0 and I or L as 1.
    expect(equalBytes(await recoveryKeyFromCode(provider, code.replace(/0/g, 'O').replace(/1/g, 'l')), recoveryKey)).toBe(true)

    const payload = await recoveryQrPayload(provider, recoveryKey)
    expect(payload).toBe(`zaman-recovery:1:${code.replace(/-/g, '')}`)
    expect(equalBytes(await recoveryKeyFromQrPayload(provider, payload), recoveryKey)).toBe(true)
  })

  test('a typing error is found', async () => {
    const words = recoveryKeyToWords(recoveryKey)
    const swapped = [...words]
    ;[swapped[3], swapped[4]] = [swapped[4], swapped[3]]
    expect(errorCode(() => recoveryKeyFromWords(swapped))).toBe('E_INVALID_INPUT')
    expect(errorCode(() => recoveryKeyFromWords([...words.slice(0, 23), 'notaword']))).toBe('E_INVALID_INPUT')
    expect(errorCode(() => recoveryKeyFromWords(words.slice(0, 12)))).toBe('E_INVALID_INPUT')

    const code = await recoveryKeyToCode(provider, recoveryKey)
    const wrongCharacter = code[5] === 'A' ? 'B' : 'A'
    const typo = code.slice(0, 5) + wrongCharacter + code.slice(6)
    expect(await errorCodeOf(() => recoveryKeyFromCode(provider, typo))).toBe('E_INVALID_INPUT')
    expect(await errorCodeOf(() => recoveryKeyFromCode(provider, code.slice(0, -5)))).toBe('E_INVALID_INPUT')
    expect(await errorCodeOf(() => recoveryKeyFromQrPayload(provider, 'other:1:ABCD'))).toBe('E_INVALID_INPUT')
  })

  test('the recovery key opens the account key, and the account key opens the copy', async () => {
    const { accountKey } = await createAccountKeys(provider, {
      accountId: '0192f7a0-0000-7000-8000-0000000000c1',
      exportKey: fixedBytes(64, 0x41),
    })
    const kit = await createRecoveryKit(provider, accountKey)

    const opened = await openAccountKeyWithRecoveryKey(provider, kit.recoveryKey, kit.unlockWrap, accountKey.id)
    expect(equalBytes(opened.bytes, accountKey.bytes)).toBe(true)
    const shown = await openRecoveryKeyCopy(provider, accountKey, kit.copy, kit.unlockWrap)
    expect(equalBytes(shown, kit.recoveryKey)).toBe(true)
    expect(equalBytes(kit.proof, await recoveryProof(provider, kit.recoveryKey))).toBe(true)
    // The proof cannot stand in for the key.
    expect(equalBytes(kit.proof, kit.recoveryKey)).toBe(false)

    const other = fixedBytes(32, 0x77)
    expect(await errorCodeOf(() => openAccountKeyWithRecoveryKey(provider, other, kit.unlockWrap, accountKey.id))).toBe('E_DECRYPT_FAILED')
  })
})
