# Releasing

Releases are automated. Push [conventional commits](https://www.conventionalcommits.org/) to `main`; CI runs the test vectors on Node and in headless Chromium, on Linux, macOS and Windows, then semantic-release computes the version, publishes to npm, tags the commit and updates the changelog. Publishing is **tokenless**: it uses npm [trusted publishing](https://docs.npmjs.com/trusted-publishers) over OIDC, so no `NPM_TOKEN` secret is stored.

Use Node 26 (see `.nvmrc`): `nvm use`.

## Before a release that changes a suite or a mobile provider

CI runs Node and Chromium only. Before you merge a change to a suite, or to the NativeScript provider, run the vectors on a real iPhone and a real Android phone with the test app, and write the result in the pull request.

A suite becomes `current` in `src/suites.ts` only in a release where every runtime passed.

## One-time setup for a new package

npm won't let you configure a trusted publisher until the package already exists, and OIDC can't perform that first publish. Bootstrap it with a throwaway stub:

1. **Publish the stub.** From your machine, logged in to an npm account with publish rights on the `@zamanapp` scope:

   ```bash
   nvm use                          # Node 26 — setup-trusted-publishing needs >= 24.4
   npm login                        # interactive; handles 2FA
   pnpm dlx setup-trusted-publishing
   ```

   This publishes a `0.0.0` stub (empty module) so the package name exists. It also writes `publishConfig.provenance: true` and repository info into `package.json`: review that diff, and keep only what is not there yet.

2. **Configure the trusted publisher** at `npmjs.com/package/@zamanapp/tashfir` → Settings → Trusted Publishers → Add:

   | Field | Value |
   | --- | --- |
   | Organization or user | `zamanapp` |
   | Repository | `tashfir` |
   | Workflow filename | `ci.yml` |
   | Allowed action | npm publish |

   Fields are case-sensitive and are **not** validated on save: a typo only surfaces at publish time.

3. **Release for real.** Push a conventional commit to `main`. semantic-release publishes the first real version (`1.0.0`), which supersedes the `0.0.0` stub.

Every later release is a push to `main`.
