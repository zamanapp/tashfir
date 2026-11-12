import { CryptoError } from './errors.ts'

/** The first byte of each envelope. A new layout of the envelope is a new version. */
export const ENVELOPE_VERSION = 0x01

export type SuiteState = 'current' | 'deprecated' | 'retired'

export interface Suite {
  id: number
  state: SuiteState
  description: string
  /** The HPKE identifiers (RFC 9180) of the public-key wraps of this suite. */
  hpke: { kemId: number; kdfId: number; aeadId: number }
  /** The plaintext size of one STREAM segment of a file. */
  fileSegmentSize: number
}

/**
 * The suite registry. A suite is defined by its test vectors: a new draft version of a part, or a
 * new parameter, is a new suite ID, never a change of an existing one.
 */
const SUITES: ReadonlyMap<number, Suite> = new Map([
  [
    0x01,
    {
      id: 0x01,
      state: 'current',
      description:
        'AES-256-GCM with a random 96-bit nonce, HKDF-SHA-256, X-Wing (draft-connolly-cfrg-xwing-kem-11) in HPKE base mode, STREAM with 64 KiB segments',
      hpke: { kemId: 0x647a, kdfId: 0x0001, aeadId: 0x0002 },
      fileSegmentSize: 64 * 1024,
    },
  ],
])

export function currentSuite(): Suite {
  for (const suite of SUITES.values()) if (suite.state === 'current') return suite
  throw new CryptoError('E_UNKNOWN_SUITE', 'The registry has no current suite')
}

/** The suite of a ciphertext to open. Unknown and retired suites fail closed. */
export function suiteForReading(id: number): Suite {
  const suite = SUITES.get(id)
  if (!suite) throw new CryptoError('E_UNKNOWN_SUITE', `Unknown suite ID ${id}`)
  if (suite.state === 'retired')
    throw new CryptoError('E_SUITE_RETIRED', `Suite ID ${id} is retired`)
  return suite
}

export type SignatureAlgorithm = 'mldsa65-ed25519'

/** The `algorithm` of a signature public key in the registry. */
export const SIGNATURE_ALGORITHMS: Readonly<
  Record<SignatureAlgorithm, { state: SuiteState; description: string }>
> = {
  'mldsa65-ed25519': {
    state: 'current',
    description: 'Composite ML-DSA-65 + Ed25519 (id-MLDSA65-Ed25519-SHA512, RFC 10073)',
  },
}
