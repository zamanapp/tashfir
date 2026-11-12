# tashfir — Agent Guide

`AGENTS.md` is a copy of this file. Edit `CLAUDE.md`, then copy it to `AGENTS.md`.

This package holds the crypto formats of Zaman. Users can read and audit this code, and a mistake here can make data unreadable for ever. Read `README.md` and `CONTRIBUTING.md` before a change.

## Rules

- Run `pnpm test` (Vitest: Node and headless Chromium) and `pnpm typecheck` after each change. Do not finish with a failing vector.
- Write commit messages as [conventional commits](https://www.conventionalcommits.org/): semantic-release reads them to choose the next version. A change of the bytes of a format is never a `fix`.
- Test files run in the browser too: no `node:*` import and no `Buffer` in `tests/`, except through `tests/providers.ts`.
- Never change the bytes that an existing suite writes. Never run `pnpm vectors` to make a failing test pass.
- Never add a dependency to the core without a reason that the person accepts. Pin crypto dependencies to an exact version.
- The core (`src/*.ts`) has no import of `node:*` and no WebCrypto call. Only `src/providers/` touches a runtime.
- Do not write your own primitive. Use the provider. HPKE, HKDF, STREAM and the composite signature are formats over the primitives, and the external vectors check them.
- Comments say why. Cite the RFC or the draft, with its version, for each format rule.
