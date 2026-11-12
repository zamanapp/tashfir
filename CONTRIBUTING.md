# Contributing

## Rules

- **Run `pnpm test` after each change.** All vectors must pass on each provider.
- **Never change the bytes of an existing suite.** A ciphertext lives for years. A new draft version, a new parameter or a new layout is a new suite ID (or a new envelope version), with new vectors. The old suite stays readable until no ciphertext uses it.
- **Never write the known-answer vectors again to make a test pass.** A changed byte in `vectors/known-answer/` means that old ciphertexts no longer open. `pnpm vectors` is only for a new suite or a new kind of vector.
- **Randomness comes only from the provider** (`randomBytes`), which uses the random generator of the operating system. Never a seeded generator.
- **Injected randomness only in tests.** The functions that take a nonce, an `eseed` or `rnd` are exported only from `@zamanapp/tashfir/testing`.
- **Keep the formats in the core.** A provider gives primitives only. The envelope, HPKE, the composite signature and STREAM are written once, in `src/`.
- **Errors never hold key bytes or plaintext.** A caller can log a `CryptoError`.

## Add a suite

1. Add the suite to `src/suites.ts` with the state `deprecated`.
2. Add its external vectors to `vectors/external/` and its known-answer vectors with `pnpm vectors`.
3. Pass the vectors on each runtime, the mobile phones too.
4. Make it `current` and the old one `deprecated`, in the same release.
5. Write the change, its date and its reason in the changelog of the release.
