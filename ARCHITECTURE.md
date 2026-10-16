# Tealbrick dist: architecture

State: verified against the repo on 2026-10-16. Claims cite paths in this repo. Anything not verified is marked UNVERIFIED. For the whole system see the system `ARCHITECTURE.md` and `SYSTEM-OVERVIEW.md`.

## 1. Pull-model mirror (`scripts/mirror.ts`)

1. Trigger: schedule, manual dispatch, or `repository_dispatch` type `registry-synced` (nothing sends it today). Runs only on `main`. `permissions: {}` at the top; the job has `contents: write` for this repo only; concurrency group `mirror`; no install step.
2. Read `index.json` and `index.jws` from `TB_INDEX_BASE` (default the platform `registry` release; with a read token, fall back to the API).
3. `verifyIndex`: compact JWS, header exactly `{alg, typ, kid}`, `alg EdDSA`, `typ tb-release-index+jws`, `kid` is the RFC 7638 thumbprint of the pinned key, signature check, exact claim set, `iss tb:releases`, `aud tb:portal`, schema `opt2.release-index/v2`, lifetime at most 180 days, not expired (30 s leeway), `indexDigest` equal to the sha256 of the canonical body, counts match. A forged, expired or altered index stops the run before any write.
4. `planMirror`: only entries whose `artifact.url` begins with this repo's release download base; the URL tag must equal `<source repo name>-<entry.tag>`; the tag `registry` and side-file names are reserved; digests must be well-formed.
5. For each item: if the dist release already has the file, check its bytes against the signed digests (a mismatch is an ALARM; it is never replaced) and add missing side files; otherwise download from the private source release with the read token, check sha256 (and sha512 when present), create the dist release if needed, upload side files first, then the tarball.
6. Registry copy: replace `index.json` then `index.jws` in release `registry` only when the new index verifies and its `iat` is not older than the copy already there.
7. Any alarm exits non-zero.

Kinds covered by code: selection is by URL host, not by `kind`. By spec the kinds are `cli` (product `cli`, tag `cli-v<ver>`) and `package` (relay, harnesses, and since C206 B6 spec, manifest, miniapp-sdk, conformance, create-tealbrick-miniapp, ui; tag `<product>-v<ver>`).

## 2. Trust

Downloads do not trust this host. The installer and `self-update` verify the signed index with their own pinned key and check the sha256 and sha512 of every tarball. This host is a convenience, not an authority.

## 3. Known gaps

- `cli` and `relay` entries are missing from the index until the first `cli-v*` tag.
- The read token must be re-scoped when repositories change visibility or move.
- Scheduled runs can lag (GitHub delays schedules of new repos); dispatch by hand after a release.
- It does not use the standard CI template (no Woodpecker file). UNVERIFIED whether intentional.
- The platform repo is public, so the mirror's API fallback for a private platform repo is not exercised.