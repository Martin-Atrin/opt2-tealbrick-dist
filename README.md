# Tealbrick dist

Public download host for the release files of Tealbrick's **private** repositories (decisions C164, C173, C175). A pull-model mirror job copies verified files from private releases. This repository holds no product source.

- Repository: `Tealbrick/opt2-tealbrick-dist` (GitHub organisation `Tealbrick`)
- Status: the repository belongs to the Tealbrick org (C206). The signed index (checked 2026-10-17) lists 38 `package` entries (spec, manifest, miniapp-sdk, conformance, create-tealbrick-miniapp, ui and legacy tarballs) that this host serves; no `cli` or `relay` entry yet. Library pins of the other repos (`@opt2-tealbrick/spec`, `manifest`, `miniapp-sdk`, `conformance`, `ui`) point to release files on this host.
- Visibility: PUBLIC by design (C164, C175).
- Licence: Apache-2.0 for the scripts, workflows and documentation (`LICENSE`). Mirrored release files keep their own licence; see `NOTICE`. The Tealbrick CLI is proprietary.

## No secrets policy

This repository is public by design. It must never contain secrets or personal data:

- No API keys, tokens, passwords, private keys, deployment secrets, `.env` files or connection strings. The only secret it uses is the repository secret `TB_PRIVATE_READ_TOKEN`, which lives in GitHub and is never printed.
- No personal names, private agent configurations or customer data, in the code, issues or pull requests.
- GitHub secret scanning and push protection are not enabled on this repository, and it has no gitleaks step or pre-commit hook. Review every change for secrets by hand.
- If a secret is committed anyway: rotate it first, then remove it from history.

## What this repo holds

- release files, one GitHub release per source release, named `<source repo>-<source tag>` (for example `opt2-tealbrick-bridge-cli-v0.1.22` with `opt2-tealbrick-cli-0.1.22.tgz`, `.sha256` and `.integrity`);
- a copy of the signed release index in the release `registry` (`index.json` + `index.jws`), the second index base of the one-line installer (`curl -fsSL https://tealbrick.com/install.sh | bash`) and of `tealbrick self-update`;
- the mirror workflow and its script (`.github/workflows/mirror.yml`, `scripts/mirror.ts`).

The private side has no write access here. The mirror reads private releases with a read-only token and writes only to this repository.

## How a file gets here (pull model, C164)

1. The platform signer (`opt2-tealbrick-platform`, registry-sync) signs a release entry whose `artifact.url` points here, with the file's `sha256` and sha512 `integrity`.
2. The mirror workflow (every 15 minutes, or by hand) reads the signed index and verifies it with the pinned release key in `keys/release-keys.json`. A forged, expired or altered index stops the run before any write.
3. For each entry that points here and is not here yet, it downloads the file from the private source release with the read-only secret `TB_PRIVATE_READ_TOKEN`, checks the bytes against the signed sha256 and sha512, and uploads the file with its `.sha256` and `.integrity` files.
4. It copies `index.json` + `index.jws` to the release `registry`, only when the new index verifies and is not older than the copy already there.

A published file is never replaced. If a file here has other bytes than the signed index says, or the source has other bytes, the run stops with an ALARM and fails; nothing is overwritten.

Downloads do not need to trust this host: the installer and `tealbrick self-update` verify the signed index with their own pinned key and refuse any file whose sha256 or sha512 does not match its signed entry.

## Quick start

```sh
npm ci --ignore-scripts
npm run typecheck && npm test       # 16 tests against a fake GitHub host: no network, no secrets
npm run mirror                      # node scripts/mirror.ts (in CI, with the secrets named below)
```

Node.js 24 or newer runs the TypeScript files directly. The mirror itself uses only Node built-ins.

## Layout

| Path | Purpose |
|---|---|
| `scripts/mirror.ts` | The mirror |
| `test/mirror.test.ts` | 16 tests |
| `keys/release-keys.json` | The ONE pinned release public key (a test asserts its `x` value; it equals the platform `registry/keys.json` today, but no test reads that file) |
| `.github/workflows/mirror.yml`, `test.yml` | Mirror (schedule `7,22,37,52 * * * *`, manual, optional `repository_dispatch`) and tests |

## Configuration

| Name | Where | What |
|---|---|---|
| `TB_PRIVATE_READ_TOKEN` | repository secret | Fine-grained token, **read-only**, resource owner `Tealbrick`: contents and release metadata of the source repos that are or become private (cli, sdk, specs, packages, bridge, tbd; only cli is private today, the others are public until the planned flip). No write scopes. Re-scope it when a repo changes visibility or moves. The real scopes of the secret cannot be read from the repo (UNVERIFIED). |
| `GITHUB_TOKEN` | built in | `contents: write` on this repository only (create releases, upload files). |
| `TB_INDEX_BASE`, `GITHUB_REPOSITORY` | optional env | Index source (default: the platform `registry` release); this repo's `owner/name`. |

## CI

This repo does not use the Woodpecker `ci-v9.9` template. GitHub Actions run `test.yml` (typecheck and tests on every push to main and pull request) and `mirror.yml`.

## How it ships

It is the distribution. Its own releases are the mirrored files.

## Documentation

- `ARCHITECTURE.md` explains the design.
- `CONTRIBUTING.md` explains how to change it.
- System documentation (overview, environments, runbooks) lives in the private repo Tealbrick/opt2-tealbrick-docs.
- `Tealbrick/opt2-tealbrick-platform`, `ci/README.md` ("Dist host"): how the signer points entries here.
