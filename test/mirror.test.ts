import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  canonicalize,
  DEFAULT_INDEX_BASE,
  type IndexBody,
  type Jwk,
  jcsDigest,
  mirror,
  planMirror,
  sideFiles,
  thumbprint,
  verifyIndex,
} from "../scripts/mirror.ts";

const DIST = "Martin-Atrin/opt2-tealbrick-dist";
const CLI = "Martin-Atrin/opt2-tealbrick-cli";
const NOW = 1_800_000_000;

function keyPair(): { jwk: Jwk; priv: KeyObject } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const j = publicKey.export({ format: "jwk" }) as Jwk;
  return { jwk: { kty: "OKP", crv: "Ed25519", x: j.x }, priv: privateKey };
}
const K = keyPair();

function signIndex(body: IndexBody, o: { iat?: number; priv?: KeyObject; jwk?: Jwk; typ?: string; digest?: string } = {}): string {
  const iat = o.iat ?? NOW - 60;
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
  const h = b64({ alg: "EdDSA", typ: o.typ ?? "tb-release-index+jws", kid: thumbprint(o.jwk ?? K.jwk) });
  const p = b64({
    iss: "tb:releases",
    aud: "tb:portal",
    iat,
    exp: iat + 90 * 86400,
    schema: "opt2.release-index/v2",
    indexDigest: o.digest ?? jcsDigest(body),
    releases: body.releases.length,
    offers: body.offers?.length ?? 0,
  });
  return `${h}.${p}.${sign(null, Buffer.from(`${h}.${p}`), o.priv ?? K.priv).toString("base64url")}\n`;
}

const tgz = Buffer.from("fake cli tarball bytes v0.2.0");
const sri = (b: Uint8Array) => `sha512-${createHash("sha512").update(b).digest("base64")}`;
const hex = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");
const cliUrl = `https://github.com/${DIST}/releases/download/opt2-tealbrick-cli-cli-v0.2.0/opt2-tealbrick-cli-0.2.0.tgz`;

function makeIndex(over: Partial<IndexBody["releases"][number]> = {}, extra: IndexBody["releases"] = []): IndexBody {
  return {
    schema: "opt2.release-index/v2",
    releases: [
      {
        id: "rel_01JA0000000000000000000009",
        product: "cli",
        kind: "cli",
        version: "0.2.0",
        repo: CLI,
        tag: "cli-v0.2.0",
        artifact: { url: cliUrl, sha256: `sha256:${hex(tgz)}`, integrity: sri(tgz) },
        ...over,
      },
      // an app entry (image) and a desktop entry on GitHub: not this host, ignored
      { id: "rel_a", product: "kanban", kind: "app", version: "0.1.0", repo: "Martin-Atrin/opt2-tealbrick-kanban", tag: "v0.1.0", artifact: null },
      {
        id: "rel_d",
        product: "tbd",
        kind: "desktop",
        version: "0.1.0",
        repo: "Martin-Atrin/opt2-tealbrick-tbd",
        tag: "v0.1.0",
        artifact: { url: "https://github.com/Martin-Atrin/opt2-tealbrick-tbd/releases/download/v0.1.0/TBD.zip", sha256: `sha256:${"a".repeat(64)}` },
      },
      ...extra,
    ],
    offers: [],
  };
}

type FakeAsset = { id: number; name: string; data: Buffer };
/** In-memory GitHub: public download URLs, the REST API and uploads; private repos need the read token, writes need the write token. */
function fakeGitHub(opts: {
  index: IndexBody;
  jws?: string;
  indexText?: string;
  source?: Buffer;
  noSourceAsset?: boolean;
  extraSources?: { tag: string; name: string; data: Buffer }[];
}) {
  let nextId = 100;
  const repos = new Map<string, Map<string, { id: number; assets: FakeAsset[] }>>();
  const rel = (repo: string, tag: string, create = false) => {
    if (!repos.has(repo)) repos.set(repo, new Map());
    const r = repos.get(repo) as Map<string, { id: number; assets: FakeAsset[] }>;
    if (!r.has(tag) && create) r.set(tag, { id: nextId++, assets: [] });
    return r.get(tag);
  };
  const add = (repo: string, tag: string, name: string, data: Buffer) => rel(repo, tag, true)?.assets.push({ id: nextId++, name, data });
  if (!opts.noSourceAsset) add(CLI, "cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz", opts.source ?? tgz);
  for (const x of opts.extraSources ?? []) add(CLI, x.tag, x.name, x.data);
  const writes: string[] = [];
  const reads: { url: string; auth: string | null }[] = [];
  const indexText = opts.indexText ?? JSON.stringify(opts.index);
  const jws = opts.jws ?? signIndex(JSON.parse(indexText) as IndexBody);
  const fetcher = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    const method = init?.method ?? "GET";
    const h = (init?.headers ?? {}) as Record<string, string>;
    const auth = h.authorization ?? null;
    reads.push({ url, auth });
    const json = (status: number, b: unknown) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
    if (url === `${DEFAULT_INDEX_BASE}/index.json`) return new Response(indexText, { status: 200 });
    if (url === `${DEFAULT_INDEX_BASE}/index.jws`) return new Response(jws, { status: 200 });
    let m = /^https:\/\/api\.github\.com\/repos\/([^/]+\/[^/]+)\/releases\/tags\/(.+)$/.exec(url);
    if (m && method === "GET") {
      const [repo, tag] = [m[1] as string, decodeURIComponent(m[2] as string)];
      if (repo === CLI && auth !== "Bearer READ") return json(404, {});
      const r = rel(repo, tag);
      return r ? json(200, { id: r.id, assets: r.assets.map((a) => ({ id: a.id, name: a.name })) }) : json(404, {});
    }
    m = /^https:\/\/api\.github\.com\/repos\/([^/]+\/[^/]+)\/releases\/assets\/(\d+)$/.exec(url);
    if (m) {
      const repo = m[1] as string;
      const id = Number(m[2]);
      const all = [...(repos.get(repo)?.values() ?? [])];
      const r = all.find((x) => x.assets.some((a) => a.id === id));
      const a = r?.assets.find((x) => x.id === id);
      if (method === "DELETE") {
        if (auth !== "Bearer WRITE" || repo !== DIST || !r || !a) return json(403, {});
        r.assets = r.assets.filter((x) => x.id !== id);
        writes.push(`delete ${a.name}`);
        return new Response(null, { status: 204 });
      }
      if (repo === CLI && auth !== "Bearer READ") return json(404, {});
      return a && h.accept === "application/octet-stream" ? new Response(new Uint8Array(a.data), { status: 200 }) : json(404, {});
    }
    m = /^https:\/\/api\.github\.com\/repos\/([^/]+\/[^/]+)\/releases$/.exec(url);
    if (m && method === "POST") {
      if (auth !== "Bearer WRITE" || m[1] !== DIST) return json(403, {});
      const tag = (JSON.parse(String(init?.body)) as { tag_name: string }).tag_name;
      if (rel(DIST, tag)) return json(422, {});
      const r = rel(DIST, tag, true) as { id: number };
      writes.push(`release ${tag}`);
      return json(201, { id: r.id });
    }
    m = /^https:\/\/uploads\.github\.com\/repos\/([^/]+\/[^/]+)\/releases\/(\d+)\/assets\?name=(.+)$/.exec(url);
    if (m && method === "POST") {
      if (auth !== "Bearer WRITE" || m[1] !== DIST) return json(403, {});
      const r = [...(repos.get(DIST)?.values() ?? [])].find((x) => x.id === Number(m?.[2]));
      const name = decodeURIComponent(m[3] as string);
      if (!r || r.assets.some((a) => a.name === name)) return json(422, { message: "already_exists" });
      const data = Buffer.from(init?.body as Uint8Array);
      r.assets.push({ id: nextId++, name, data });
      writes.push(`upload ${name}`);
      return json(201, { size: data.length });
    }
    return json(500, { unexpected: `${method} ${url}` });
  }) as typeof fetch;
  const distFile = (tag: string, name: string) => rel(DIST, tag)?.assets.find((a) => a.name === name)?.data;
  return { fetcher, writes, reads, add, distFile };
}

const run = (gh: ReturnType<typeof fakeGitHub>, o: { read?: string | undefined; keys?: Jwk[]; nowS?: number } = {}) =>
  mirror({ fetcher: gh.fetcher, readToken: "read" in o ? o.read : "READ", writeToken: "WRITE", distRepo: DIST, keys: o.keys ?? [K.jwk], nowS: o.nowS ?? NOW, log: () => {} });

test("JCS matches the manifest rules (sorted keys, no whitespace, -0, unicode)", () => {
  assert.equal(canonicalize({ b: [1, -0, "é"], a: null, c: { y: true, x: 1.5 } }), '{"a":null,"b":[1,0,"é"],"c":{"x":1.5,"y":true}}');
  assert.throws(() => canonicalize({ x: Number.NaN }), /non-finite/);
});

test("the pinned key equals the platform release key set (registry/keys.json) the index is signed with", () => {
  const keys = (JSON.parse(readFileSync(new URL("../keys/release-keys.json", import.meta.url), "utf8")) as { keys: Jwk[] }).keys;
  assert.equal(keys.length, 1);
  assert.match(thumbprint(keys[0] as Jwk), /^[A-Za-z0-9_-]{43}$/);
  assert.equal(keys[0]?.x, "H7nxFrNugQLVOqEXVIB4aOg83Jn19UCosd27fqnoPPI");
});

test("index verification refuses every forgery (fires) and accepts the good case (quiet)", () => {
  const body = makeIndex();
  const text = JSON.stringify(body);
  assert.equal(verifyIndex(signIndex(body), text, [K.jwk], NOW).claims.releases, 3);
  const other = keyPair();
  assert.throws(() => verifyIndex(signIndex(body, { priv: other.priv, jwk: other.jwk }), text, [K.jwk], NOW), /not a pinned release key/);
  assert.throws(() => verifyIndex(signIndex(body, { priv: other.priv }), text, [K.jwk], NOW), /bad signature/);
  assert.throws(() => verifyIndex(signIndex(body, { typ: "JWT" }), text, [K.jwk], NOW), /alg\/typ/);
  assert.throws(() => verifyIndex(signIndex(body, { digest: `sha256:${"0".repeat(64)}` }), text, [K.jwk], NOW), /indexDigest/);
  const tampered = JSON.stringify(makeIndex({ artifact: { url: cliUrl, sha256: `sha256:${"b".repeat(64)}`, integrity: sri(tgz) } }));
  assert.throws(() => verifyIndex(signIndex(body), tampered, [K.jwk], NOW), /indexDigest/);
  assert.throws(() => verifyIndex(signIndex(body, { iat: NOW - 100 * 86400 }), text, [K.jwk], NOW), /expired/);
  assert.throws(() => verifyIndex(signIndex(body, { iat: NOW + 3600 }), text, [K.jwk], NOW), /future/);
  assert.throws(() => verifyIndex("a.b", text, [K.jwk], NOW), /compact JWS/);
});

test("plan: only entries on this dist host; the tag must be <repo>-<entry tag>", () => {
  const p = planMirror(makeIndex(), DIST);
  assert.deepEqual(p.problems, []);
  assert.deepEqual(
    p.items.map((i) => [i.distTag, i.file, i.sourceRepo, i.sourceTag]),
    [["opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz", CLI, "cli-v0.2.0"]],
  );
  const bad = planMirror(makeIndex({ tag: "cli-v0.1.0" }), DIST);
  assert.match(bad.problems.join(), /url tag opt2-tealbrick-cli-cli-v0\.2\.0 != opt2-tealbrick-cli-cli-v0\.1\.0/);
  const reserved = planMirror(makeIndex({ artifact: { url: `https://github.com/${DIST}/releases/download/registry/index.json`, sha256: `sha256:${"a".repeat(64)}` } }), DIST);
  assert.equal(reserved.items.length, 0);
  assert.equal(reserved.problems.length, 1);
});

test("first run publishes the tarball + side files under the index tag and copies the index to `registry`; a second run writes nothing", async () => {
  const gh = fakeGitHub({ index: makeIndex() });
  const r = await run(gh);
  assert.deepEqual(r.alarms, []);
  assert.deepEqual(r.published, ["opt2-tealbrick-cli-cli-v0.2.0/opt2-tealbrick-cli-0.2.0.tgz"]);
  assert.equal(r.indexCopied, true);
  assert.deepEqual(gh.distFile("opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz"), tgz);
  const sides = sideFiles("opt2-tealbrick-cli-0.2.0.tgz", tgz);
  for (const s of sides) assert.equal(gh.distFile("opt2-tealbrick-cli-cli-v0.2.0", s.name)?.toString(), s.body);
  assert.match(sides[0]?.body ?? "", /^[0-9a-f]{64} {2}opt2-tealbrick-cli-0\.2\.0\.tgz\n$/);
  assert.equal(gh.distFile("registry", "index.json")?.toString(), JSON.stringify(makeIndex()));
  assert.ok(gh.distFile("registry", "index.jws"));
  // the read token only ever goes to the CLI repo; the write token only to this repo
  for (const x of gh.reads) {
    if (x.auth === "Bearer READ") assert.ok(x.url.includes(`/repos/${CLI}/`), x.url);
    if (x.auth === "Bearer WRITE") assert.ok(x.url.includes(`/repos/${DIST}/`), x.url);
  }
  const n = gh.writes.length;
  const again = await run(gh);
  assert.deepEqual(again.alarms, []);
  assert.deepEqual(again.published, []);
  assert.deepEqual(again.present, ["opt2-tealbrick-cli-cli-v0.2.0/opt2-tealbrick-cli-0.2.0.tgz"]);
  assert.equal(again.indexCopied, false);
  assert.equal(gh.writes.length, n, "idempotent: no write on the second run");
});

test("source bytes that differ from the signed digests are never published (alarm)", async () => {
  const gh = fakeGitHub({ index: makeIndex(), source: Buffer.from("tampered") });
  const r = await run(gh);
  assert.match(r.alarms.join(), /SOURCE BYTES DIFFER/);
  assert.equal(gh.distFile("opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz"), undefined);
  assert.ok(!gh.writes.some((w) => w.includes("opt2-tealbrick-cli-0.2.0")));
  // the sha512 is checked too, not only the sha256
  const gh2 = fakeGitHub({ index: makeIndex({ artifact: { url: cliUrl, sha256: `sha256:${hex(tgz)}`, integrity: `sha512-${"A".repeat(86)}==` } }) });
  assert.match((await run(gh2)).alarms.join(), /sha512 integrity/);
});

test("an existing published asset with different bytes is never replaced (alarm); a conflicting side file blocks the publish", async () => {
  const gh = fakeGitHub({ index: makeIndex() });
  gh.add(DIST, "opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz", Buffer.from("old other bytes"));
  const r = await run(gh);
  assert.match(r.alarms.join(), /PUBLISHED BYTES DIFFER/);
  assert.deepEqual(gh.distFile("opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz"), Buffer.from("old other bytes"));
  assert.ok(!gh.writes.some((w) => w.startsWith("delete opt2-tealbrick-cli")));
  const gh2 = fakeGitHub({ index: makeIndex() });
  gh2.add(DIST, "opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz.sha256", Buffer.from("wrong\n"));
  const r2 = await run(gh2);
  assert.match(r2.alarms.join(), /\.sha256: exists with different content/);
  assert.equal(gh2.distFile("opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz"), undefined, "no tarball next to a wrong checksum");
});

test("a forged index stops the run before any write", async () => {
  const forged = keyPair();
  const gh = fakeGitHub({ index: makeIndex(), jws: signIndex(makeIndex(), { priv: forged.priv, jwk: forged.jwk }) });
  await assert.rejects(run(gh), /not a pinned release key/);
  assert.deepEqual(gh.writes, []);
});

test("without the read token: the index is still copied, the missing file is an alarm (misconfigured secret)", async () => {
  const gh = fakeGitHub({ index: makeIndex() });
  const r = await run(gh, { read: undefined });
  assert.equal(r.indexCopied, true);
  assert.match(r.alarms.join(), /no TB_PRIVATE_READ_TOKEN/);
  assert.ok(!gh.reads.some((x) => x.url.includes(`/repos/${CLI}/`)));
});

test("the signed entry names a file the private release does not have: alarm", async () => {
  const gh = fakeGitHub({ index: makeIndex(), noSourceAsset: true });
  assert.match((await run(gh)).alarms.join(), /has no asset opt2-tealbrick-cli-0\.2\.0\.tgz/);
});

test("registry copy: an older verified index never replaces a newer copy (no rollback); a newer one does", async () => {
  const newer = makeIndex();
  const gh = fakeGitHub({ index: newer, jws: signIndex(newer, { iat: NOW - 10 }) });
  await run(gh);
  const kept = gh.distFile("registry", "index.jws")?.toString();
  const older = fakeGitHub({ index: newer, jws: signIndex(newer, { iat: NOW - 5000 }) });
  // seed the older run's dist with the newer copy
  older.add(DIST, "registry", "index.json", Buffer.from(JSON.stringify(newer)));
  older.add(DIST, "registry", "index.jws", Buffer.from(kept ?? ""));
  older.add(DIST, "opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz", tgz);
  const r = await run(older);
  assert.match(r.alarms.join(), /NEWER than the source index/);
  assert.equal(older.distFile("registry", "index.jws")?.toString(), kept);
  assert.equal(r.indexCopied, false);
});

test("the workflow: schedule + manual, contents: write only, read secret by name, no install step, node runs the TS file", () => {
  const wf = readFileSync(new URL("../.github/workflows/mirror.yml", import.meta.url), "utf8");
  assert.match(wf, /TB_PRIVATE_READ_TOKEN: \$\{\{ secrets\.TB_PRIVATE_READ_TOKEN \}\}/);
  assert.match(wf, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/);
  assert.match(wf, /contents: write/);
  assert.doesNotMatch(wf, /packages: write|actions: write|id-token/);
  assert.match(wf, /node scripts\/mirror\.ts/);
  assert.doesNotMatch(wf, /npm (ci|install)/);
  assert.match(wf, /workflow_dispatch/);
  assert.match(wf, /schedule:/);
  for (const u of wf.matchAll(/uses: (\S+)/g)) assert.match(u[1] as string, /@[0-9a-f]{40}$/, "actions pinned by commit");
});

test("C181: a kind package entry (relay) on this host is mirrored like cli: <repo>-<tag>, bytes checked against the signed digests", async () => {
  const relay = Buffer.from("fake relay tarball bytes v0.1.0");
  const relayUrl = `https://github.com/${DIST}/releases/download/opt2-tealbrick-cli-relay-v0.1.0/opt2-tealbrick-relay-0.1.0.tgz`;
  const entry = {
    id: "rel_01JA0000000000000000000010",
    product: "relay",
    kind: "package",
    version: "0.1.0",
    repo: CLI,
    tag: "relay-v0.1.0",
    artifact: { url: relayUrl, sha256: `sha256:${hex(relay)}`, integrity: sri(relay) },
  };
  const index = makeIndex({}, [entry]);
  assert.deepEqual(
    planMirror(index, DIST).items.map((i) => [i.distTag, i.file, i.sourceTag]),
    [
      ["opt2-tealbrick-cli-cli-v0.2.0", "opt2-tealbrick-cli-0.2.0.tgz", "cli-v0.2.0"],
      ["opt2-tealbrick-cli-relay-v0.1.0", "opt2-tealbrick-relay-0.1.0.tgz", "relay-v0.1.0"],
    ],
  );
  const gh = fakeGitHub({ index, extraSources: [{ tag: "relay-v0.1.0", name: "opt2-tealbrick-relay-0.1.0.tgz", data: relay }] });
  const r = await run(gh);
  assert.deepEqual(r.alarms, []);
  assert.deepEqual(r.published.sort(), ["opt2-tealbrick-cli-cli-v0.2.0/opt2-tealbrick-cli-0.2.0.tgz", "opt2-tealbrick-cli-relay-v0.1.0/opt2-tealbrick-relay-0.1.0.tgz"]);
  assert.deepEqual(gh.distFile("opt2-tealbrick-cli-relay-v0.1.0", "opt2-tealbrick-relay-0.1.0.tgz"), relay);
  // fires: tampered relay bytes in the private release are never published
  const bad = fakeGitHub({ index, extraSources: [{ tag: "relay-v0.1.0", name: "opt2-tealbrick-relay-0.1.0.tgz", data: Buffer.from("evil") }] });
  const rb = await run(bad);
  assert.match(rb.alarms.join(), /opt2-tealbrick-relay-0\.1\.0\.tgz: SOURCE BYTES DIFFER/);
  assert.equal(bad.distFile("opt2-tealbrick-cli-relay-v0.1.0", "opt2-tealbrick-relay-0.1.0.tgz"), undefined);
});

test("first scheduled run before any dist entry, without the read token: copies only the index, no alarm (C177 state)", async () => {
  const index = makeIndex();
  index.releases = index.releases.filter((x) => x.kind !== "cli");
  const gh = fakeGitHub({ index, noSourceAsset: true });
  const r = await run(gh, { read: undefined });
  assert.deepEqual(r.alarms, []);
  assert.deepEqual(r.published, []);
  assert.equal(r.indexCopied, true);
  assert.ok(!gh.reads.some((x) => x.url.includes(`/repos/${CLI}/`)), "no private-repo request without a dist entry");
});
