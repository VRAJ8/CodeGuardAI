/** @jest-environment node */
// Loader tests: limits and skip rules come from rules.generated.json, ZIPs are built in-test with fflate, GitHub is a
// mocked fetch. The ZIP reader is also held to Python's load_zip end to end: the golden corpus, zipped, must load
// and scan to exactly the report parity.golden.json records.
import { zipSync } from "fflate";
import { Blob } from "buffer";
import GOLDEN from "./parity.golden.json";
import { LIMITS } from "./lang";
import {
  SourceError, filePath, loadFromFiles, loadFromGitHub, loadFromZip, loadSource, normalizePath, resetClock,
} from "./sources";
import { runJob, toAnalysis, userMessage } from "./worker";
import { scan } from "./index";

jest.mock("./index", () => ({ ENGINE_VERSION: "browser-test", scan: jest.fn() }));

const NUL = String.fromCharCode(0);
// TextEncoder output belongs to the outer realm under jest, where fflate's `instanceof Uint8Array` fails: copy it.
const bytes = (s) => new Uint8Array(new TextEncoder().encode(s));
const substitute = (text) =>
  Object.entries(GOLDEN.placeholders).reduce((t, [name, parts]) => t.split(name).join(parts.join("")), text);
const paths = (r) => r.files.map((f) => f.path);
const none = { filtered: 0, too_large: 0, binary: 0, over_limit: 0 };

/** A File-like with lazy contents, so a test can claim any size without allocating it. */
const fakeFile = (path, content = "x\n", size) => {
  const data = typeof content === "string" ? bytes(content) : content;
  return { name: path.split("/").pop(), path, size: size ?? data.length, arrayBuffer: jest.fn(async () => data.slice().buffer) };
};

const fakeReport = (files) => ({
  metrics: { total_files: files.length, total_lines: 3, languages: { javascript: 1 }, avg_complexity: 1, maintainability_index: 90 },
  security_issues: [{ rule_id: "CG-EVAL", severity: "high" }], bug_risks: [], dependencies: [], overall_score: 88.5,
  grade: "B", severity_counts: { critical: 0, high: 1, medium: 0, low: 0 }, owasp_counts: {}, scanner_counts: { patterns: 1 },
  scanners_run: ["patterns", "secrets", "complexity"], suppressed: 0, suppressed_issues: [],
  errors: ["osv: dependency audit did not run (TypeError: Failed to fetch)"], warnings: ["a.js:1: malformed"],
  duration_ms: 5,
});

beforeEach(() => {
  scan.mockReset();
  scan.mockImplementation(async (files, { onProgress = () => {} } = {}) => {
    onProgress("Running secret & pattern rules", 20);
    onProgress("Measuring complexity & maintainability", 70);
    return fakeReport(files);
  });
});

// ---------------------------------------------------------------------------------------------- files

describe("loadFromFiles", () => {
  test("normalizePath drops ./ and / prefixes and turns backslashes into /", () => {
    expect(["./dir/a.js", "/dir/a.js", "dir\\sub\\a.js", ".//x.py", "a.js", "../up.js"].map(normalizePath))
      .toEqual(["dir/a.js", "dir/a.js", "dir/sub/a.js", "x.py", "a.js", "../up.js"]);
  });

  test("filePath prefers file-selector's relativePath, then path, webkitRelativePath, name", () => {
    expect([
      filePath({ relativePath: "./r.js", path: "/abs/r.js", webkitRelativePath: "w/r.js", name: "r.js" }),
      filePath({ path: "/dir/p.js", webkitRelativePath: "", name: "p.js" }),
      filePath({ webkitRelativePath: "proj/w.js", name: "w.js" }),
      filePath({ name: "n.js" }),
    ]).toEqual(["./r.js", "/dir/p.js", "proj/w.js", "n.js"]);
  });

  test("a dropped folder loses its shared top folder (dropzone paths), sorted by path", async () => {
    const r = await loadFromFiles([fakeFile("/proj/src/b.py", "print(1)\n"), fakeFile("./proj/a.js"), fakeFile("/proj/README.md")]);
    expect(paths(r)).toEqual(["a.js", "src/b.py"]);
    expect(r.name).toBe("proj");
    expect(r.skipped).toEqual({ ...none, filtered: 1 });
    expect(r.files[1]).toEqual({ path: "src/b.py", content: "print(1)\n", language: "python", lines: 2 });
  });

  test("webkitdirectory paths and {file, path} pairs (what the client posts to the worker)", async () => {
    const picked = { ...fakeFile("ignored.js"), path: undefined, webkitRelativePath: "app\\lib\\x.js" };
    const pair = { file: { ...fakeFile("whatever"), path: undefined }, path: "app/y.go" };
    const r = await loadFromFiles([picked, pair], { name: "My app" });
    expect(paths(r)).toEqual(["lib/x.js", "y.go"]);
    expect(r.name).toBe("My app");
  });

  test("loose files keep their names; a single one names the scan", async () => {
    expect(paths(await loadFromFiles([fakeFile("./b.js"), fakeFile("./a.ts")]))).toEqual(["a.ts", "b.js"]);
    expect((await loadFromFiles([fakeFile("./a.ts")])).name).toBe("a");
    expect((await loadFromFiles([fakeFile("x/a.ts"), fakeFile("y/b.ts")])).name).toBe("Local files");
  });

  test("skip rules: vendored dirs, lockfiles, bundles, unsupported types and .. paths are never read", async () => {
    const skipped = ["p/node_modules/x/i.js", "p/dist/out.js", "p/yarn.lock", "p/app.min.js", "p/logo.png",
      "p/src/__pycache__/m.py", "p/../escape.js"].map((p) => fakeFile(p));
    const r = await loadFromFiles([...skipped, fakeFile("p/.env", "A=1\n"), fakeFile("p/Dockerfile", "FROM x\n")]);
    expect(paths(r)).toEqual([".env", "Dockerfile"]);
    expect(r.skipped).toEqual({ ...none, filtered: skipped.length });
    skipped.forEach((f) => expect(f.arrayBuffer).not.toHaveBeenCalled());
  });

  test(`MAX_FILES (${LIMITS.maxFiles}): the first files by path, the rest counted and noted`, async () => {
    const files = Array.from({ length: LIMITS.maxFiles + 5 }, (_, i) => fakeFile(`s/f${String(i).padStart(4, "0")}.js`));
    const r = await loadFromFiles(files);
    expect(r.files).toHaveLength(LIMITS.maxFiles);
    expect(r.files[LIMITS.maxFiles - 1].path).toBe(`f${String(LIMITS.maxFiles - 1).padStart(4, "0")}.js`);
    expect(r.skipped).toEqual({ ...none, over_limit: 5 });
    expect(r.notes).toEqual([`Scanned the first ${LIMITS.maxFiles} files; 5 more supported files were not scanned (scan limit).`]);
    expect(files[LIMITS.maxFiles].arrayBuffer).not.toHaveBeenCalled();
  });

  test("a file over MAX_FILE_BYTES is skipped without being read", async () => {
    const big = fakeFile("big.js", "x", LIMITS.maxFileBytes + 1);
    const r = await loadFromFiles([big, fakeFile("ok.js", "x", LIMITS.maxFileBytes)]);
    expect(paths(r)).toEqual(["ok.js"]);
    expect(r.skipped).toEqual({ ...none, too_large: 1 });
    expect(big.arrayBuffer).not.toHaveBeenCalled();
  });

  test("MAX_TOTAL_BYTES: the file that crosses it and everything after are left out", async () => {
    const size = 500 * 1000;
    const fit = Math.floor(LIMITS.maxTotalBytes / size);
    const files = Array.from({ length: fit + 3 }, (_, i) => fakeFile(`h/f${String(i).padStart(3, "0")}.js`, "x", size));
    const r = await loadFromFiles([...files, fakeFile("h/zz.png", "x", size)]);
    expect(r.files).toHaveLength(fit);
    expect(r.skipped).toEqual({ ...none, filtered: 1, over_limit: 3 });
    expect(r.notes[0]).toMatch(/^Stopped at 30 MB of source; 3 more supported files were not scanned/);
  });

  test("binary sniff: a NUL within the first 1024 characters skips the file; later ones don't", async () => {
    const r = await loadFromFiles([fakeFile("a/bin.js", `ab${NUL}cd`), fakeFile("a/late.js", `${"é".repeat(1024)}${NUL}`),
      fakeFile("a/latin.js", Uint8Array.of(0x61, 0xe9, 0x62, 0x0a))]);
    expect(paths(r)).toEqual(["late.js", "latin.js"]);
    expect(r.skipped).toEqual({ ...none, binary: 1 });
    expect(r.files[1].content).toBe("ab\n"); // bytes.decode("utf-8", errors="ignore")
  });

  test("an aborted signal stops the loader", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(loadFromFiles([fakeFile("a.js")], { signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
  });
});

// ---------------------------------------------------------------------------------------------- ZIP

/** Patch every central-directory and local header of a zip in place. */
function patchHeaders(zip, { flagsOr = 0, flagsAnd = 0xffff } = {}) {
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  for (let i = 0; i + 4 <= zip.length; i++) {
    const sig = view.getUint32(i, true);
    const at = sig === 0x02014b50 ? i + 8 : sig === 0x04034b50 ? i + 6 : -1;
    if (at >= 0) view.setUint16(at, (view.getUint16(at, true) & flagsAnd) | flagsOr, true);
  }
  return zip;
}

describe("loadFromZip", () => {
  const project = () => zipSync({
    "widget-main": {}, // a directory entry
    "widget-main/src/app.js": bytes("const x = run(input);\n"),
    "widget-main/src/util.py": bytes("import os\r\nos.system(cmd)\r\n"),
    "widget-main/node_modules/lib/index.js": bytes("evil()"),
    "widget-main/package-lock.json": bytes("{}"),
    "widget-main/package.json": bytes('{"dependencies": {"lodash": "4.17.0"}}'),
    "widget-main/logo.png": Uint8Array.of(137, 80, 78, 71, 0),
    "widget-main/bin.js": bytes(`ab${NUL}cd`),
    "widget-main/big.js": bytes("a".repeat(LIMITS.maxFileBytes + 1)),
    "widget-main/empty.ts": new Uint8Array(0),
  });

  test("happy path: the wrapper folder is stripped and load_zip's filters apply, in archive order", async () => {
    const r = await loadFromZip(project());
    expect(r.files.map(({ path, language, lines }) => [path, language, lines])).toEqual([
      ["src/app.js", "javascript", 2], ["src/util.py", "python", 3], ["package.json", "json", 1], ["empty.ts", "typescript", 1],
    ]);
    expect(r.files[1].content).toBe("import os\r\nos.system(cmd)\r\n"); // newlines are the engine's business
    expect(r.skipped).toEqual({ ...none, filtered: 3, too_large: 1, binary: 1 });
    expect(r.name).toBe("archive");
  });

  test("File/Blob, ArrayBuffer and Uint8Array inputs read the same; a File names the scan by its stem", async () => {
    const zip = project();
    const blob = Object.assign(new Blob([zip]), { name: "widget-main.zip" });
    const results = await Promise.all([loadFromZip(blob), loadFromZip(zip.slice().buffer), loadFromZip(zip)]);
    expect(results.map(paths)).toEqual([paths(results[2]), paths(results[2]), paths(results[2])]);
    expect(results[0].name).toBe("widget-main");
    expect((await loadFromZip(zip, { name: "Named" })).name).toBe("Named");
  });

  test("zip-slip: absolute and .. members are rejected, as PurePosixPath sees them", async () => {
    const r = await loadFromZip(zipSync({
      "../evil.js": bytes("evil"), "a/../../b.py": bytes("b"), "/abs.js": bytes("abs"), "//net.js": bytes("net"),
      "ok/..x.js": bytes("fine"), "..\\win.js": bytes("one odd name on POSIX, as in Python"),
    }));
    expect(paths(r)).toEqual(["ok/..x.js", "..\\win.js"]);
    expect(r.skipped).toEqual({ ...none, filtered: 4 });
  });

  test("__MACOSX junk is dropped, but still counts as a second top folder (as in Python)", async () => {
    const r = await loadFromZip(zipSync({ "proj/a.js": bytes("a"), "__MACOSX/proj/._a.js": bytes("junk") }));
    expect(paths(r)).toEqual(["proj/a.js"]);
  });

  test("stored members, an archive comment and cp437 names (no UTF-8 flag)", async () => {
    const stored = await loadFromZip(zipSync({ "s/a.js": bytes("stored\n") }, { level: 0, comment: "hello" }));
    expect(stored.files[0]).toMatchObject({ path: "a.js", content: "stored\n" });
    // fflate writes "café.js" as UTF-8 with flag bit 11; without the flag Python reads those bytes as cp437
    const cp437 = await loadFromZip(patchHeaders(zipSync({ "café.js": bytes("x\n") }), { flagsAnd: ~0x800 & 0xffff }));
    expect(paths(cp437)).toEqual(["caf├⌐.js"]);
  });

  test(`MAX_FILES, MAX_FILE_BYTES and MAX_TOTAL_BYTES as load_zip applies them`, async () => {
    const many = {};
    for (let i = 0; i < LIMITS.maxFiles + 3; i++) many[`m/f${String(i).padStart(3, "0")}.js`] = bytes(`v${i}\n`);
    const r = await loadFromZip(zipSync(many));
    expect(r.files).toHaveLength(LIMITS.maxFiles);
    expect(r.skipped).toEqual({ ...none, over_limit: 3 });

    const heavy = {};
    for (let i = 0; i < 64; i++) heavy[`h/f${String(i).padStart(2, "0")}.js`] = bytes("b".repeat(500 * 1000));
    const h = await loadFromZip(zipSync(heavy));
    expect(h.files).toHaveLength(62); // 62 x 500 KB fits in 30 MiB, the 63rd crosses it
    expect(h.skipped).toEqual({ ...none, over_limit: 2 });
  });

  test("too many members, not a zip, truncated, CRC mismatch, encrypted: clear errors", async () => {
    const members = {};
    for (let i = 0; i <= LIMITS.maxMembers; i++) members[`n/${i}.txt`] = new Uint8Array(0);
    await expect(loadFromZip(zipSync(members, { level: 0 }))).rejects.toThrow(`Archive has too many entries (${LIMITS.maxMembers + 1}).`);

    await expect(loadFromZip(bytes("PK not a zip at all"))).rejects.toThrow(new SourceError("That file isn't a valid ZIP archive."));
    const good = zipSync({ "t/a.js": bytes("hello\n".repeat(50)) });
    await expect(loadFromZip(good.subarray(0, good.length - 30))).rejects.toThrow("isn't a valid ZIP archive");

    const corrupt = zipSync({ "c/a.js": bytes("content\n") }, { level: 0 });
    corrupt[corrupt.indexOf(0x63, 30 + "c/a.js".length)] = 0x43; // flip a byte of the stored data
    await expect(loadFromZip(corrupt)).rejects.toThrow('That ZIP archive is damaged ("c/a.js" can\'t be read).');

    await expect(loadFromZip(patchHeaders(zipSync({ "e/a.js": bytes("x") }), { flagsOr: 1 }))).rejects.toThrow("is encrypted");
    // like Python, only members that are actually read can fail the archive
    const unread = await loadFromZip(patchHeaders(zipSync({ "e/a.png": bytes("x") }), { flagsOr: 1 }));
    expect(unread.files).toEqual([]);
    await expect(loadFromZip({ not: "a zip" })).rejects.toThrow("Choose a .zip file");
  });

  test("the golden corpus, zipped, loads exactly the files Python scans", async () => {
    const zip = zipSync(Object.fromEntries(Object.entries(GOLDEN.corpus).map(([p, c]) => [p, bytes(substitute(c))])));
    const r = await loadFromZip(zip);
    expect(r.files.map(({ path, language, lines }) => ({ path, language, lines }))).toEqual(GOLDEN.expected.files);
  });
});

// ---------------------------------------------------------------------------------------------- GitHub

const SHA = "0123456789abcdef0123456789abcdef01234567";
const headersOf = (h) => ({ get: (k) => h[k.toLowerCase()] ?? null });
const res = (status, body, headers = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  headers: headersOf(headers),
  json: async () => (typeof body === "string" ? JSON.parse(body) : body),
  text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
  arrayBuffer: async () => (body instanceof Uint8Array ? body : bytes(String(body))).slice().buffer,
});
const blobSha = (path) => Array.from(bytes(path)).reduce((h, b) => (h * 31 + b) % 1e9, 7).toString(16).padStart(40, "0");
const blob = (path, content) => ({ path, mode: "100644", type: "blob", sha: blobSha(path), size: bytes(content).length });

/** A fake GitHub: repo meta, commits/{ref} (sha media type), the recursive tree, raw files and git blobs. */
function fakeGitHub({ files = {}, tree, meta = {}, truncated = false, route = () => null, delay = () => 0 } = {}) {
  const api = "https://api.github.com/repos/acme/widget";
  const raw = `https://raw.githubusercontent.com/acme/widget/${SHA}/`;
  const entries = tree || Object.entries(files).map(([p, c]) => blob(p, c));
  const calls = [];
  const fetchImpl = jest.fn(async (url, init = {}) => {
    calls.push({ url, headers: init.headers || {} });
    const custom = route(url, calls);
    if (custom) return custom;
    if (url === api) return res(200, { default_branch: "main", private: false, stargazers_count: 7, description: "A widget", language: "JavaScript", html_url: "https://github.com/acme/widget", ...meta });
    if (url.startsWith(`${api}/commits/`)) return res(200, `${SHA}\n`);
    if (url === `${api}/git/trees/${SHA}?recursive=1`) return res(200, { sha: "t", tree: entries, truncated });
    const path = url.startsWith(raw) ? url.slice(raw.length).split("/").map(decodeURIComponent).join("/")
      : url.startsWith(`${api}/git/blobs/`) ? entries.find((e) => url.endsWith(e.sha))?.path : null;
    if (path != null && path in files) {
      await new Promise((resolve) => setTimeout(resolve, delay(path)));
      return res(200, bytes(files[path]));
    }
    return res(404, { message: "Not Found" });
  });
  return { fetchImpl, calls, raws: () => calls.filter((c) => c.url.startsWith("https://raw.githubusercontent.com/")) };
}

describe("loadFromGitHub", () => {
  const URL_ = "https://github.com/acme/widget";

  test("happy path: meta, commit, tree, then raw files at the commit, in tree order", async () => {
    const files = {
      "src/app.js": "run(x)\n", "docs/hello world#1.js": "a\n", "node_modules/x/i.js": "n", "bin.js": `a${NUL}b`,
      "README.md": "# hi", "package.json": "{}",
    };
    const tree = [
      { path: "src", mode: "040000", type: "tree", sha: "d" }, ...Object.entries(files).map(([p, c]) => blob(p, c)),
      { ...blob("big.js", "x"), size: LIMITS.maxFileBytes + 1 }, { ...blob("link.js", "x"), mode: "120000" },
      { path: "sub", mode: "160000", type: "commit", sha: "s" },
    ];
    const gh = fakeGitHub({ files, tree });
    const progress = [];
    const r = await loadFromGitHub(` ${URL_}/ `, { fetchImpl: gh.fetchImpl, onProgress: (s, p) => progress.push(p) });
    expect(paths(r)).toEqual(["src/app.js", "docs/hello world#1.js", "package.json"]);
    expect(r.skipped).toEqual({ ...none, filtered: 3, too_large: 1, binary: 1 });
    expect(r.name).toBe("acme/widget");
    expect(r.repo_meta).toEqual({ owner: "acme", repo: "widget", ref: "main", sha: SHA, url: "https://github.com/acme/widget",
      stars: 7, description: "A widget", language: "JavaScript", private: false });
    expect(gh.calls.slice(0, 3).map((c) => c.url)).toEqual([
      "https://api.github.com/repos/acme/widget", "https://api.github.com/repos/acme/widget/commits/main",
      `https://api.github.com/repos/acme/widget/git/trees/${SHA}?recursive=1`]);
    expect(gh.raws().map((c) => c.url)).toContain(`https://raw.githubusercontent.com/acme/widget/${SHA}/docs/hello%20world%231.js`);
    expect(gh.raws()).toHaveLength(4); // node_modules, README, big.js and the symlink are never fetched
    expect(progress).toEqual([...progress].sort((a, b) => a - b));
    expect(progress[progress.length - 1]).toBe(100);
  });

  test("a token goes to api.github.com only; raw.githubusercontent.com fails every CORS preflight", async () => {
    const gh = fakeGitHub({ files: { "a.js": "a\n" } });
    await loadFromGitHub(URL_, { token: "tok-123", fetchImpl: gh.fetchImpl });
    const api = gh.calls.filter((c) => c.url.startsWith("https://api.github.com/"));
    expect(api.map((c) => c.headers.Authorization)).toEqual(["Bearer tok-123", "Bearer tok-123", "Bearer tok-123"]);
    expect(gh.raws().map((c) => c.headers)).toEqual([{}]);
  });

  test("a private repo's files come from the git blobs API with the raw media type", async () => {
    const gh = fakeGitHub({ files: { "a.js": "private\n" }, meta: { private: true } });
    const r = await loadFromGitHub(URL_, { token: "tok-123", fetchImpl: gh.fetchImpl });
    expect(r.files[0].content).toBe("private\n");
    expect(gh.raws()).toEqual([]);
    expect(gh.calls[3]).toEqual({ url: `https://api.github.com/repos/acme/widget/git/blobs/${blobSha("a.js")}`,
      headers: { Accept: "application/vnd.github.raw+json", Authorization: "Bearer tok-123" } });
    expect(r.repo_meta.private).toBe(true);
  });

  test("/tree/<ref> URLs: a branch with slashes is resolved to a commit; a full SHA is used as is", async () => {
    const gh = fakeGitHub({ files: { "a.js": "a\n" } });
    const r = await loadFromGitHub(`${URL_}/tree/release/v2.0`, { fetchImpl: gh.fetchImpl });
    expect(gh.calls[1].url).toBe("https://api.github.com/repos/acme/widget/commits/release/v2.0");
    expect(r.repo_meta).toMatchObject({ ref: "release/v2.0", sha: SHA });

    const pinned = fakeGitHub({ files: { "a.js": "a\n" } });
    await loadFromGitHub(`${URL_}/tree/${SHA.toUpperCase()}`, { fetchImpl: pinned.fetchImpl });
    expect(pinned.calls.map((c) => c.url).some((u) => u.includes("/commits/"))).toBe(false);
  });

  test("invalid URLs are refused before any request", async () => {
    const gh = fakeGitHub();
    for (const url of ["https://gitlab.com/acme/widget", "github.com/acme/widget", "https://github.com/acme", "", null]) {
      await expect(loadFromGitHub(url, { fetchImpl: gh.fetchImpl }))
        .rejects.toThrow(new SourceError("Enter a repository URL like https://github.com/owner/repo"));
    }
    expect(gh.fetchImpl).not.toHaveBeenCalled();
  });

  test("404: the repo must be public, or the token must be able to read it", async () => {
    const gh = fakeGitHub({ route: () => res(404, { message: "Not Found" }) });
    await expect(loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl }))
      .rejects.toThrow("Repository acme/widget not found. It must be public, or add a GitHub token that can read it.");
    await expect(loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl, token: "t" })).rejects.toThrow("or the token can't read it");
  });

  test("403 rate limit: the reset time from X-RateLimit-Reset, and a token suggestion", async () => {
    const reset = Math.floor(Date.now() / 1000) + 30 * 60;
    const limited = () => res(403, { message: "API rate limit exceeded for 1.2.3.4." },
      { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(reset) });
    const gh = fakeGitHub({ route: limited });
    const err = await loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl }).catch((e) => e);
    expect(err).toBeInstanceOf(SourceError);
    expect(err.message).toBe(`GitHub's API rate limit for requests without a token (60 an hour) is used up. It resets at `
      + `${resetClock(reset)} (in 30 min). Add a GitHub token to raise it to 5,000 an hour.`);
    await expect(loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl, token: "t" }))
      .rejects.toThrow(`GitHub's API rate limit for this token is used up. It resets at ${resetClock(reset)}`);
  });

  test("secondary rate limits, bad tokens, unknown refs, empty repos and network failures", async () => {
    const at = (status, body, headers) => fakeGitHub({ route: (url) => (url.includes("/commits/") ? res(status, body, headers) : null) });
    const cases = [
      [fakeGitHub({ route: () => res(403, { message: "You have exceeded a secondary rate limit." }, { "retry-after": "42" }) }),
        "GitHub is throttling requests. Try again in 42 seconds."],
      [fakeGitHub({ route: () => res(401, { message: "Bad credentials" }) }), "GitHub rejected the token (401 Bad credentials)"],
      [at(422, { message: "No commit found for SHA: nope" }), 'Couldn\'t find branch, tag or commit "main" in acme/widget.'],
      [at(409, { message: "Git Repository is empty." }), "acme/widget is empty."],
      [fakeGitHub({ route: () => { throw new TypeError("Failed to fetch"); } }), "Couldn't reach api.github.com."],
    ];
    for (const [gh, message] of cases) await expect(loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl })).rejects.toThrow(message);
  });

  test("a truncated tree is scanned as far as it goes, with a note", async () => {
    const gh = fakeGitHub({ files: { "a.js": "a\n" }, truncated: true });
    const r = await loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl });
    expect(paths(r)).toEqual(["a.js"]);
    expect(r.notes).toEqual(["GitHub listed only part of this very large repository, so some files were not scanned. "
      + "Scan a ZIP or folder of it for full coverage."]);
  });

  test("MAX_FILES in tree order however downloads finish; binaries don't use up the budget", async () => {
    const files = {};
    for (let i = 0; i < LIMITS.maxFiles + 60; i++) files[`f/${String(i).padStart(3, "0")}.js`] = i % 10 === 0 ? `${NUL}bin` : `v${i}\n`;
    const order = Object.keys(files);
    const gh = fakeGitHub({ files, delay: (p) => (order.indexOf(p) * 7919) % 5 }); // finishes out of order
    const r = await loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl });
    const expected = order.filter((p, i) => i % 10 !== 0).slice(0, LIMITS.maxFiles);
    expect(paths(r)).toEqual(expected);
    const read = order.indexOf(expected[expected.length - 1]) + 1;
    expect(r.skipped).toEqual({ ...none, binary: Math.ceil(read / 10), over_limit: order.length - read });
    expect(gh.raws().length).toBeLessThanOrEqual(read + 16); // downloads run at most 16 files ahead
  });

  test("a slow file at the limit does not let the other downloads run ahead without bound", async () => {
    const files = {};
    for (let i = 0; i < LIMITS.maxFiles + 100; i++) files[`f/${String(i).padStart(3, "0")}.js`] = `v${i}\n`;
    const last = Object.keys(files)[LIMITS.maxFiles - 1];
    const gh = fakeGitHub({ files, delay: (p) => (p === last ? 60 : 0) });
    const r = await loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl });
    expect(r.files[r.files.length - 1].path).toBe(last);
    expect(gh.raws().length).toBeLessThanOrEqual(LIMITS.maxFiles + 16);
  });

  test("MAX_TOTAL_BYTES from tree sizes: later files are not downloaded at all", async () => {
    const tree = Array.from({ length: 70 }, (_, i) => ({ ...blob(`h/${i}.js`, "x"), size: 500 * 1000 }));
    const gh = fakeGitHub({ tree, files: Object.fromEntries(tree.map((e) => [e.path, "x"])) });
    const r = await loadFromGitHub(URL_, { fetchImpl: gh.fetchImpl });
    expect(r.files).toHaveLength(62);
    expect(r.skipped.over_limit).toBe(8);
    expect(gh.raws()).toHaveLength(62);
  });

  test("a raw 5xx is retried once; a persistent failure fails the scan instead of skipping the file", async () => {
    let flaky = 0;
    const once = fakeGitHub({ files: { "a.js": "a\n" }, route: (url) => (url.endsWith("/a.js") && !flaky++ ? res(502, "") : null) });
    expect(paths(await loadFromGitHub(URL_, { fetchImpl: once.fetchImpl }))).toEqual(["a.js"]);
    const down = fakeGitHub({ files: { "a.js": "a\n" }, route: (url) => (url.endsWith("/a.js") ? res(503, "") : null) });
    await expect(loadFromGitHub(URL_, { fetchImpl: down.fetchImpl })).rejects.toThrow("Couldn't download a.js from GitHub (HTTP 503).");
    const limited = fakeGitHub({ files: { "a.js": "a\n" }, route: (url) => (url.endsWith("/a.js") ? res(429, "") : null) });
    await expect(loadFromGitHub(URL_, { fetchImpl: limited.fetchImpl })).rejects.toThrow("raw.githubusercontent.com is rate-limiting");
  });
});

// ---------------------------------------------------------------------------------------------- jobs

describe("runJob (worker.js)", () => {
  test("load + scan resolves to an analysis the report pages read like a server one", async () => {
    const progress = [];
    const a = await runJob({ kind: "files", input: [fakeFile("p/a.js"), fakeFile("p/b.py")], osv: false },
      (stage, pct) => progress.push([stage, pct]));
    expect(scan).toHaveBeenCalledWith(expect.any(Array), expect.objectContaining({ osv: false }));
    expect(scan.mock.calls[0][0].map((f) => f.path)).toEqual(["a.js", "b.py"]);
    expect(a).toMatchObject({
      ...fakeReport([1, 2]), name: "p", source_type: "files", source_url: null, repo_meta: null, status: "completed",
      engine_version: "browser-test", mode: "browser", issue_count: 1, grade: "B",
      scan_errors: fakeReport([]).errors, scan_warnings: fakeReport([]).warnings, skipped: none, source_notes: [],
      progress: { stage: "Done", pct: 100 },
    });
    expect(a.analysis_id).toMatch(/^local-[0-9a-f]{12}$/);
    expect(new Date(a.created_at).toISOString()).toBe(a.created_at);
    const pcts = progress.map(([, pct]) => pct);
    expect(pcts).toEqual([...pcts].sort((x, y) => x - y));
    expect(Math.max(...pcts)).toBeLessThan(100);
  });

  test("a GitHub job keeps its URL and repo meta, and never the token", async () => {
    const gh = fakeGitHub({ files: { "a.js": "a\n" } });
    const a = await runJob({ kind: "github", input: " https://github.com/acme/widget ", token: "tok-secret-1", name: "" },
      () => {}, { fetchImpl: gh.fetchImpl });
    expect(a).toMatchObject({ name: "acme/widget", source_type: "github", source_url: "https://github.com/acme/widget" });
    expect(a.repo_meta.sha).toBe(SHA);
    expect(scan.mock.calls[0][1].osv).toBe(true);
    expect(JSON.stringify(a)).not.toContain("tok-secret-1");
  });

  test("nothing to scan is a user-facing error that says what was skipped", async () => {
    const err = await runJob({ kind: "files", input: [fakeFile("p/logo.png"), fakeFile("p/x.js", `${NUL}`)] }).catch((e) => e);
    expect(userMessage(err)).toBe("No supported source files were found (skipped: 1 unsupported or vendored, 1 binary).");
    expect(scan).not.toHaveBeenCalled();
  });

  test("errors map to user-facing messages; cancelling stops the job", async () => {
    expect(userMessage(new SourceError("Nope."))).toBe("Nope.");
    expect(userMessage(new TypeError("x is undefined"))).toBe("Scan failed: TypeError");
    const controller = new AbortController();
    scan.mockImplementation(async (files, { onProgress }) => {
      controller.abort();
      onProgress("Running secret & pattern rules", 20);
      return fakeReport(files);
    });
    const err = await runJob({ kind: "files", input: [fakeFile("a.js")] }, () => {}, { signal: controller.signal }).catch((e) => e);
    expect(err.name).toBe("AbortError");
    expect(userMessage(err)).toBe("Scan cancelled.");
    await expect(loadSource({ kind: "svn", input: "x" })).rejects.toThrow('Unknown source kind "svn".');
  });

  test("toAnalysis names a ZIP scan by the job's name first, then the loader's", () => {
    const source = { name: "archive", files: [], skipped: none, notes: ["n"] };
    const a = toAnalysis(fakeReport([]), source, { kind: "zip", name: "  Mine  " }, { startedAt: new Date(0), id: "abc" });
    expect(a).toMatchObject({ analysis_id: "local-abc", name: "Mine", source_type: "zip", source_notes: ["n"], created_at: "1970-01-01T00:00:00.000Z" });
  });

  describe("with the real engine", () => {
    const { volatile, expected } = GOLDEN;
    const strip = (report) => Object.fromEntries(Object.entries(report).filter(([k]) => !volatile.report.includes(k)));
    const reportOf = (analysis) => strip(Object.fromEntries(Object.keys(expected.report).map((k) => [k, analysis[k]])));
    const corpus = Object.entries(GOLDEN.corpus).map(([p, c]) => [p, substitute(c)]);

    beforeEach(() => scan.mockImplementation(jest.requireActual("./index").scan));

    test("a ZIP of the golden corpus scans to the golden report", async () => {
      const zip = zipSync(Object.fromEntries(corpus.map(([p, c]) => [p, bytes(c)])));
      const a = await runJob({ kind: "zip", input: zip, osv: false });
      expect(reportOf(a)).toEqual(strip(expected.report));
      expect(Object.keys(a)).toEqual(expect.arrayContaining([...Object.keys(expected.report), ...volatile.report]));
    });

    test("the golden corpus served as a GitHub tree scans to the golden report", async () => {
      const gh = fakeGitHub({ files: Object.fromEntries(corpus) });
      const a = await runJob({ kind: "github", input: "https://github.com/acme/widget", osv: false }, () => {}, { fetchImpl: gh.fetchImpl });
      expect(reportOf(a)).toEqual(strip(expected.report));
    });
  });
});
