/**
 * C164/C175 pull mirror. Runs in the PUBLIC repo Martin-Atrin/opt2-tealbrick-dist (GitHub Actions, schedule + manual).
 *
 * 1. Reads the signed release index (index.json + index.jws) and verifies it with the PINNED release keys
 *    (keys/release-keys.json): EdDSA JWS, typ tb-release-index+jws, kid = RFC 7638 thumbprint of a pinned key, claims
 *    iss tb:releases / aud tb:portal / schema opt2.release-index/v2, not expired, indexDigest = sha256 of the RFC 8785 (JCS) body,
 *    release/offer counts. Nothing from an index that fails is used.
 * 2. For every release whose `artifact.url` is on THIS dist host (`https://github.com/<dist repo>/releases/download/<tag>/<file>`),
 *    the tag must be `<source repo name>-<entry.tag>`. If the file is not there yet, it downloads `<file>` from the release
 *    `entry.tag` of the (private) source repo with the READ-ONLY token, checks the bytes against the signed `sha256` (and
 *    `integrity` when the entry has one), and publishes it with `<file>.sha256` + `<file>.integrity` under `<tag>`.
 * 3. Copies index.json + index.jws to the release `registry` of this repo (C175: second index base for the installer), only when
 *    the new index verifies and is not older (claims.iat) than the copy already there.
 *
 * Never re-uploads an existing asset with different bytes: a published file whose bytes differ from the signed digests (or a
 * checksum file that differs) is an ALARM: nothing is replaced, the run exits non-zero. Index copies are the one exception (they
 * are meant to change; the signature makes a stale copy harmless and the iat rule prevents a rollback).
 *
 * Env: TB_PRIVATE_READ_TOKEN (read-only: contents + releases of the private repos), GITHUB_TOKEN (this repo, contents: write),
 * GITHUB_REPOSITORY (owner/name of this repo), optional TB_INDEX_BASE (default: the platform `registry` release).
 * Only node: built-ins (no install step in the workflow).
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const OWNER = "Martin-Atrin";
export const DEFAULT_DIST_REPO = `${OWNER}/opt2-tealbrick-dist`;
export const PLATFORM_REPO = `${OWNER}/opt2-tealbrick-platform`;
export const DEFAULT_INDEX_BASE = `https://github.com/${PLATFORM_REPO}/releases/download/registry`;
export const REGISTRY_TAG = "registry";
export const INDEX_TYP = "tb-release-index+jws";
export const READ_TOKEN_ENV = "TB_PRIVATE_READ_TOKEN";
const API = "https://api.github.com";
const UPLOADS = "https://uploads.github.com";
const MAX_LIFETIME_S = 180 * 86400;
const LEEWAY_S = 30;

export type Jwk = { kty: string; crv: string; x: string };
export interface IndexEntry {
  id: string;
  product: string;
  kind: string;
  version: string;
  repo: string;
  tag: string | null;
  artifact: { url: string; sha256: string; integrity?: string } | null;
}
export interface IndexBody {
  schema: string;
  releases: IndexEntry[];
  offers?: unknown[];
}
export interface Claims {
  iss: string;
  aud: string;
  iat: number;
  exp: number;
  schema: string;
  indexDigest: string;
  releases: number;
  offers: number;
}

// ---------- verification (pure) ----------

/** RFC 8785 canonical JSON (same rules as @opt2-tealbrick/manifest canonicalize). */
export function canonicalize(v: unknown): string {
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      if (!Number.isFinite(v)) throw new TypeError("jcs: non-finite number");
      return Object.is(v, -0) ? "0" : String(v);
    case "string":
      if (!v.isWellFormed()) throw new TypeError("jcs: lone surrogate");
      return JSON.stringify(v);
    case "object": {
      if (Array.isArray(v)) return `[${v.map((e) => canonicalize(e)).join(",")}]`;
      const proto = Object.getPrototypeOf(v);
      if (proto !== Object.prototype && proto !== null) throw new TypeError("jcs: only plain objects");
      const o = v as Record<string, unknown>;
      return `{${Object.keys(o)
        .sort()
        .map((k) => `${JSON.stringify(k)}:${canonicalize(o[k])}`)
        .join(",")}}`;
    }
    default:
      throw new TypeError(`jcs: unsupported ${typeof v}`);
  }
}

export function jcsDigest(v: unknown): string {
  return `sha256:${createHash("sha256").update(canonicalize(v)).digest("hex")}`;
}

export function thumbprint(jwk: Jwk): string {
  return createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest("base64url");
}

/** Verifies the index envelope against the pinned keys and the body. Returns the claims or throws (nothing unverified is used). */
export function verifyIndex(jwsText: string, bodyText: string, keys: Jwk[], nowS: number): { claims: Claims; body: IndexBody } {
  const parts = jwsText.trim().split(".");
  if (parts.length !== 3) throw new Error("index.jws is not a compact JWS");
  const [h, p, s] = parts as [string, string, string];
  const header = JSON.parse(Buffer.from(h, "base64url").toString("utf8")) as Record<string, unknown>;
  if (Object.keys(header).sort().join(",") !== "alg,kid,typ") throw new Error("index.jws header must be exactly {alg, typ, kid}");
  if (header.alg !== "EdDSA" || header.typ !== INDEX_TYP) throw new Error(`index.jws: alg/typ ${String(header.alg)}/${String(header.typ)} refused`);
  const key = keys.find((k) => k.kty === "OKP" && k.crv === "Ed25519" && thumbprint(k) === header.kid);
  if (!key) throw new Error(`index.jws: kid ${String(header.kid)} is not a pinned release key`);
  const pub = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: key.x }, format: "jwk" });
  if (!verify(null, Buffer.from(`${h}.${p}`), pub, Buffer.from(s, "base64url"))) throw new Error("index.jws: bad signature");
  const c = JSON.parse(Buffer.from(p, "base64url").toString("utf8")) as Claims;
  const want = "aud,exp,iat,indexDigest,iss,offers,releases,schema";
  if (Object.keys(c).sort().join(",") !== want) throw new Error("index.jws: unexpected claim set");
  if (c.iss !== "tb:releases" || c.aud !== "tb:portal" || c.schema !== "opt2.release-index/v2") throw new Error("index.jws: iss/aud/schema refused");
  if (!Number.isInteger(c.iat) || !Number.isInteger(c.exp) || c.exp <= c.iat || c.exp - c.iat > MAX_LIFETIME_S) throw new Error("index.jws: bad lifetime");
  if (nowS > c.exp + LEEWAY_S) throw new Error("index.jws: expired");
  if (c.iat > nowS + LEEWAY_S) throw new Error("index.jws: issued in the future");
  const body = JSON.parse(bodyText) as IndexBody;
  if (jcsDigest(body) !== c.indexDigest) throw new Error("index.json does not match the signed indexDigest");
  const n = Array.isArray(body.releases) ? body.releases.length : -1;
  const m = Array.isArray(body.offers) ? body.offers.length : 0;
  if (c.releases !== n || c.offers !== m) throw new Error("index.json counts do not match the signature");
  return { claims: c, body };
}

export function sha256Hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}
export function sha512Integrity(b: Uint8Array): string {
  return `sha512-${createHash("sha512").update(b).digest("base64")}`;
}

/** The checksum side files, byte for byte as the opt2 release template writes them (ci-v9.5). */
export function sideFiles(name: string, data: Uint8Array): { name: string; body: string }[] {
  return [
    { name: `${name}.sha256`, body: `${sha256Hex(data)}  ${name}\n` },
    { name: `${name}.integrity`, body: `${sha512Integrity(data)}\n` },
  ];
}

/** Bytes vs the signed entry: null = match, else why not. */
export function bytesProblem(data: Uint8Array, a: { sha256: string; integrity?: string }): string | null {
  if (`sha256:${sha256Hex(data)}` !== a.sha256) return `sha256 ${sha256Hex(data)} != signed ${a.sha256}`;
  if (a.integrity !== undefined && sha512Integrity(data) !== a.integrity) return "sha512 integrity != signed integrity";
  return null;
}

export interface MirrorItem {
  entry: string; // product@version
  sourceRepo: string; // owner/name (private)
  sourceTag: string; // release tag in the source repo
  distTag: string; // release tag here
  file: string;
  artifact: { sha256: string; integrity?: string };
}

/** Which files of a verified index belong on this dist host. Malformed entries for this host are problems (alarms). Pure. */
export function planMirror(body: IndexBody, distRepo: string): { items: MirrorItem[]; problems: string[] } {
  const base = `https://github.com/${distRepo}/releases/download/`;
  const items: MirrorItem[] = [];
  const problems: string[] = [];
  for (const r of body.releases ?? []) {
    const url = r?.artifact?.url;
    if (typeof url !== "string" || !url.startsWith(base)) continue;
    const where = `${r.product}@${r.version}`;
    const m = /^([A-Za-z0-9._-]+)\/([A-Za-z0-9._-]+)$/.exec(url.slice(base.length));
    const repoName = /^Martin-Atrin\/(opt2-tealbrick-[a-z0-9-]+)$/.exec(r.repo ?? "")?.[1];
    if (!m || !repoName || typeof r.tag !== "string" || !/^[A-Za-z0-9._-]+$/.test(r.tag)) {
      problems.push(`${where}: url/repo/tag not mirrorable (${url})`);
      continue;
    }
    const [, distTag, file] = m as unknown as [string, string, string];
    if (distTag !== `${repoName}-${r.tag}`) {
      problems.push(`${where}: url tag ${distTag} != ${repoName}-${r.tag}`);
      continue;
    }
    if (distTag === REGISTRY_TAG || file.endsWith(".sha256") || file.endsWith(".integrity")) {
      problems.push(`${where}: reserved name ${distTag}/${file}`);
      continue;
    }
    const a = r.artifact as { sha256: string; integrity?: string };
    if (!/^sha256:[0-9a-f]{64}$/.test(a.sha256) || (a.integrity !== undefined && !/^sha512-[A-Za-z0-9+/]{86}==$/.test(a.integrity))) {
      problems.push(`${where}: malformed signed digests`);
      continue;
    }
    items.push({ entry: where, sourceRepo: r.repo, sourceTag: r.tag, distTag, file, artifact: { sha256: a.sha256, ...(a.integrity ? { integrity: a.integrity } : {}) } });
  }
  return { items, problems };
}

// ---------- GitHub I/O (injected fetch for tests) ----------

type Fetch = typeof fetch;
interface Asset {
  id: number;
  name: string;
}
interface Release {
  id: number;
  assets: Asset[];
}

class GitHub {
  private readonly f: Fetch;
  private readonly token: string | undefined;
  constructor(f: Fetch, token: string | undefined) {
    this.f = f;
    this.token = token;
  }
  private headers(accept = "application/vnd.github+json", extra: Record<string, string> = {}): Record<string, string> {
    return { accept, "x-github-api-version": "2022-11-28", ...(this.token ? { authorization: `Bearer ${this.token}` } : {}), ...extra };
  }
  async release(repo: string, tag: string): Promise<Release | null> {
    const r = await this.f(`${API}/repos/${repo}/releases/tags/${encodeURIComponent(tag)}`, { headers: this.headers() });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`read release ${repo}@${tag}: HTTP ${r.status}`);
    const j = (await r.json()) as { id: number; assets?: Asset[] };
    return { id: j.id, assets: (j.assets ?? []).map((a) => ({ id: a.id, name: a.name })) };
  }
  async download(repo: string, id: number): Promise<Uint8Array> {
    // GitHub answers with a redirect to its object store; fetch drops the authorization header on that cross-origin hop.
    const r = await this.f(`${API}/repos/${repo}/releases/assets/${id}`, { headers: this.headers("application/octet-stream"), redirect: "follow" });
    if (!r.ok) throw new Error(`download asset ${id} of ${repo}: HTTP ${r.status}`);
    return new Uint8Array(await r.arrayBuffer());
  }
  async createRelease(repo: string, tag: string): Promise<Release> {
    const r = await this.f(`${API}/repos/${repo}/releases`, {
      method: "POST",
      headers: this.headers("application/vnd.github+json", { "content-type": "application/json" }),
      body: JSON.stringify({ tag_name: tag, name: tag, prerelease: false }),
    });
    if (r.status !== 201) throw new Error(`create release ${repo}@${tag}: HTTP ${r.status}`);
    const j = (await r.json()) as { id: number };
    return { id: j.id, assets: [] };
  }
  async upload(repo: string, releaseId: number, name: string, data: Uint8Array, type: string): Promise<void> {
    const r = await this.f(`${UPLOADS}/repos/${repo}/releases/${releaseId}/assets?name=${encodeURIComponent(name)}`, {
      method: "POST",
      headers: this.headers("application/vnd.github+json", { "content-type": type }),
      body: new Uint8Array(data),
    });
    if (r.status !== 201) throw new Error(`upload ${name}: HTTP ${r.status}`);
    const j = (await r.json()) as { size?: number };
    if (j.size !== undefined && j.size !== data.length) throw new Error(`upload ${name}: size ${j.size} != ${data.length}`);
  }
  async deleteAsset(repo: string, id: number): Promise<void> {
    const r = await this.f(`${API}/repos/${repo}/releases/assets/${id}`, { method: "DELETE", headers: this.headers() });
    if (r.status !== 204) throw new Error(`delete asset ${id}: HTTP ${r.status}`);
  }
}

export interface MirrorOptions {
  fetcher?: Fetch;
  readToken: string | undefined;
  writeToken: string;
  distRepo?: string;
  indexBase?: string;
  keys: Jwk[];
  nowS: number;
  log?: (line: string) => void;
}
export interface MirrorResult {
  published: string[]; // "<tag>/<file>"
  present: string[];
  alarms: string[];
  indexCopied: boolean;
}

async function fetchIndexFiles(o: MirrorOptions, f: Fetch): Promise<{ body: string; jws: string }> {
  const base = o.indexBase ?? DEFAULT_INDEX_BASE;
  const get = async (name: string): Promise<string | null> => {
    const r = await f(`${base}/${name}`, { redirect: "follow" });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`${base}/${name}: HTTP ${r.status}`);
    return r.text();
  };
  let body = await get("index.json");
  let jws = await get("index.jws");
  if ((body === null || jws === null) && o.readToken && base === DEFAULT_INDEX_BASE) {
    // the platform repo went private (C154): read its `registry` release with the read token
    const gh = new GitHub(f, o.readToken);
    const rel = await gh.release(PLATFORM_REPO, REGISTRY_TAG);
    const pick = async (n: string) => {
      const a = rel?.assets.find((x) => x.name === n);
      return a ? Buffer.from(await gh.download(PLATFORM_REPO, a.id)).toString("utf8") : null;
    };
    body = await pick("index.json");
    jws = await pick("index.jws");
  }
  if (body === null || jws === null) throw new Error(`release index not found at ${base}`);
  return { body, jws };
}

/** One mirror run. Throws only for an index that cannot be read or verified; everything else lands in the result. */
export async function mirror(o: MirrorOptions): Promise<MirrorResult> {
  const f = o.fetcher ?? fetch;
  const log = o.log ?? ((l: string) => console.log(`mirror: ${l}`));
  const distRepo = o.distRepo ?? DEFAULT_DIST_REPO;
  const out: MirrorResult = { published: [], present: [], alarms: [], indexCopied: false };
  const files = await fetchIndexFiles(o, f);
  const { claims, body } = verifyIndex(files.jws, files.body, o.keys, o.nowS);
  log(`index verified (iat ${claims.iat}, ${claims.releases} releases)`);

  const dist = new GitHub(f, o.writeToken);
  const src = new GitHub(f, o.readToken);
  const plan = planMirror(body, distRepo);
  out.alarms.push(...plan.problems);
  const releases = new Map<string, Release | null>();
  const distRelease = async (tag: string) => {
    if (!releases.has(tag)) releases.set(tag, await dist.release(distRepo, tag));
    return releases.get(tag) ?? null;
  };

  /** Adds missing checksum side files; an existing one with other content is an alarm (never replaced). */
  const ensureSides = async (rel: Release, tag: string, file: string, data: Uint8Array): Promise<boolean> => {
    let ok = true;
    for (const s of sideFiles(file, data)) {
      const old = rel.assets.find((a) => a.name === s.name);
      if (old) {
        if (old.id >= 0 && Buffer.from(await dist.download(distRepo, old.id)).toString("utf8") !== s.body) {
          out.alarms.push(`${tag}/${s.name}: exists with different content; not replaced`);
          ok = false;
        }
        continue;
      }
      await dist.upload(distRepo, rel.id, s.name, Buffer.from(s.body), "text/plain");
      rel.assets.push({ id: -1, name: s.name });
    }
    return ok;
  };

  for (const it of plan.items) {
    const at = `${it.distTag}/${it.file}`;
    try {
      const rel = await distRelease(it.distTag);
      const existing = rel?.assets.find((a) => a.name === it.file);
      if (rel && existing) {
        const data = await dist.download(distRepo, existing.id);
        const problem = bytesProblem(data, it.artifact);
        if (problem) out.alarms.push(`${at}: PUBLISHED BYTES DIFFER from the signed index (${problem}); not replaced`);
        else if (await ensureSides(rel, it.distTag, it.file, data)) out.present.push(at);
        continue;
      }
      if (!o.readToken) {
        out.alarms.push(`${at}: not mirrored yet and no ${READ_TOKEN_ENV} secret`);
        continue;
      }
      const srel = await src.release(it.sourceRepo, it.sourceTag);
      const sasset = srel?.assets.find((a) => a.name === it.file);
      if (!sasset) {
        out.alarms.push(`${at}: the signed index names it, but ${it.sourceRepo}@${it.sourceTag} has no asset ${it.file}`);
        continue;
      }
      const data = await src.download(it.sourceRepo, sasset.id);
      const problem = bytesProblem(data, it.artifact);
      if (problem) {
        out.alarms.push(`${at}: SOURCE BYTES DIFFER from the signed index (${problem}); not published`);
        continue;
      }
      const target = rel ?? (await dist.createRelease(distRepo, it.distTag));
      releases.set(it.distTag, target);
      // side files first: a conflicting one stops the publish before the tarball goes up
      if (!(await ensureSides(target, it.distTag, it.file, data))) continue;
      await dist.upload(distRepo, target.id, it.file, data, "application/octet-stream");
      target.assets.push({ id: -1, name: it.file });
      out.published.push(at);
      log(`published ${at} (${it.entry}, sha256 ok${it.artifact.integrity ? ", sha512 ok" : ""})`);
    } catch (e) {
      out.alarms.push(`${at}: ${(e as Error).message}`);
    }
  }

  // C175: second index base. Replace only with a verified index that is not older than the copy already there.
  try {
    const rel = (await distRelease(REGISTRY_TAG)) ?? (await dist.createRelease(distRepo, REGISTRY_TAG));
    releases.set(REGISTRY_TAG, rel);
    const cur = {
      json: rel.assets.find((a) => a.name === "index.json"),
      jws: rel.assets.find((a) => a.name === "index.jws"),
    };
    let replace = true;
    if (cur.json && cur.jws) {
      const curJws = Buffer.from(await dist.download(distRepo, cur.jws.id)).toString("utf8");
      const curJson = Buffer.from(await dist.download(distRepo, cur.json.id)).toString("utf8");
      if (curJws === files.jws && curJson === files.body) replace = false;
      else {
        let curIat = -1;
        try {
          curIat = verifyIndex(curJws, curJson, o.keys, o.nowS).claims.iat;
        } catch {
          curIat = -1; // a broken or expired copy is always replaced by a verified one
        }
        if (curIat > claims.iat) {
          replace = false;
          out.alarms.push(`registry: the copy here (iat ${curIat}) is NEWER than the source index (iat ${claims.iat}); not rolled back`);
        }
      }
    }
    if (replace) {
      // index.json first, then index.jws: a reader between the two sees a pair that fails verification and moves on (C175)
      for (const [name, text, type] of [
        ["index.json", files.body, "application/json"],
        ["index.jws", files.jws, "text/plain"],
      ] as const) {
        const old = rel.assets.find((a) => a.name === name);
        if (old) await dist.deleteAsset(distRepo, old.id);
        await dist.upload(distRepo, rel.id, name, Buffer.from(text), type);
      }
      out.indexCopied = true;
      log(`copied index.json + index.jws to ${distRepo}@${REGISTRY_TAG} (iat ${claims.iat})`);
    } else log("registry copy is current");
  } catch (e) {
    out.alarms.push(`registry: ${(e as Error).message}`);
  }
  return out;
}

async function main(): Promise<void> {
  const writeToken = process.env.GITHUB_TOKEN;
  if (!writeToken) throw new Error("GITHUB_TOKEN missing (the workflow passes the built-in token)");
  const keys = (JSON.parse(readFileSync(new URL("../keys/release-keys.json", import.meta.url), "utf8")) as { keys: Jwk[] }).keys;
  const r = await mirror({
    readToken: process.env[READ_TOKEN_ENV] || undefined,
    writeToken,
    distRepo: process.env.GITHUB_REPOSITORY || DEFAULT_DIST_REPO,
    indexBase: process.env.TB_INDEX_BASE || undefined,
    keys,
    nowS: Math.floor(Date.now() / 1000),
  });
  console.log(`mirror: published ${r.published.length}, present ${r.present.length}, index copied ${r.indexCopied}`);
  if (r.alarms.length) {
    for (const a of r.alarms) console.error(`mirror: ALARM ${a}`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((e: unknown) => {
    console.error(`mirror: ALARM ${(e as Error).message}`);
    process.exit(1);
  });
}
