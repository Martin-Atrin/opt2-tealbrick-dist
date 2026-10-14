# opt2-tealbrick-dist

Public download host for the release files of Teal Brick's **private** repositories (decisions C164, C173, C175).
This repository holds no product source. It holds:

- release files, one GitHub release per source release, named `<source repo>-<source tag>`
  (for example `opt2-tealbrick-cli-cli-v0.2.0` with `opt2-tealbrick-cli-0.2.0.tgz`, `.sha256` and `.integrity`);
- a copy of the signed release index in the release `registry` (`index.json` + `index.jws`), the second index base
  of the one-line installer (`curl -fsSL https://tealbrick.com/install.sh | bash`) and of `tealbrick self-update`;
- the mirror workflow and its script (`.github/workflows/mirror.yml`, `scripts/mirror.ts`).

## How a file gets here (pull model, C164)

1. The platform signer (`opt2-tealbrick-platform`, registry-sync) signs a release entry whose `artifact.url` points here,
   with the file's `sha256` and sha512 `integrity`.
2. The mirror workflow (every 15 minutes, or by hand) reads the signed index and verifies it with the pinned release key
   in `keys/release-keys.json`. A forged, expired or altered index stops the run before any write.
3. For each entry that points here and is not here yet, it downloads the file from the private source release with the
   read-only secret `TB_PRIVATE_READ_TOKEN`, checks the bytes against the signed sha256 and sha512, and uploads the file
   with its `.sha256` and `.integrity` files.
4. It copies `index.json` + `index.jws` to the release `registry`, only when the new index verifies and is not older
   than the copy already there.

A published file is never replaced. If a file here has other bytes than the signed index says, or the source has other
bytes, the run stops with an ALARM and fails; nothing is overwritten. The private side has no write access here; this
repository only reads from it.

Downloads do not need to trust this host: the installer and `tealbrick self-update` verify the signed index with their
own pinned key and refuse any file whose sha256 or sha512 does not match its signed entry.

## Secrets and permissions

| Name | Where | What |
|---|---|---|
| `TB_PRIVATE_READ_TOKEN` | repository secret | fine-grained token, **read-only**: Contents + (release) metadata of the private source repos (today `opt2-tealbrick-cli`; add `opt2-tealbrick-platform` when it goes private). No write scopes. |
| `GITHUB_TOKEN` | built in | `contents: write` on this repository only (create releases, upload files). |

## Development

```sh
npm ci --ignore-scripts
npm run typecheck
npm test          # fake GitHub host: no network, no secrets
```

Node.js 24 or newer runs the TypeScript files directly. The mirror itself uses only Node built-ins.

## Licence

The scripts and workflow files of this repository are Apache-2.0 (`LICENSE`). Mirrored release files keep their own
licence; see `NOTICE`. The Teal Brick CLI is proprietary.
