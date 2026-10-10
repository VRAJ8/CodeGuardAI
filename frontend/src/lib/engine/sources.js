// Source loaders for the in-browser engine: a port of backend/codeguard/sources.py (load_zip's limits, skip rules,
// path-traversal rejection and _make's decoding) for File objects, ZIP archives and public GitHub repositories. The
// rules and limits come from rules.generated.json through lang.js; nothing here talks to the CodeGuard backend.
import { inflateSync } from "fflate";
import {
  LIMITS, detectLanguage, parseGithubUrl, posixParts, pyStrip, shouldSkip, sourceFileFromBytes, stripCommonPrefix,
  suffixOf,
} from "./lang";

/** User-facing error while loading sources (sources.SourceError). */
export class SourceError extends Error {
  constructor(message) {
    super(message);
    this.name = "SourceError";
  }
}

const abortError = () => Object.assign(new Error("Scan cancelled."), { name: "AbortError" });
const throwIfAborted = (signal) => {
  if (signal?.aborted) throw abortError();
};
const stem = (name) => name.slice(0, name.length - suffixOf(name).length);

// ---------------------------------------------------------------------------------------------- limits

/** sources._make plus load_zip's read guard: {file}, or {why} when the bytes are passed over. */
function make(rel, bytes) {
  if (bytes.length > LIMITS.maxFileBytes) return { why: "too_large" };
  const file = sourceFileFromBytes(rel, bytes);
  return file ? { file } : { why: "binary" };
}

/** load_zip's bookkeeping. Python stops at the first member that takes the total over MAX_TOTAL_BYTES and once
 *  MAX_FILES files are loaded; this keeps classifying what follows, so `skipped` can say how much was left out. */
function collector() {
  const files = [];
  const skipped = { filtered: 0, too_large: 0, binary: 0, over_limit: 0 };
  let total = 0;
  let stopped = null; // "bytes" | "files": the limit that ended the scan
  return {
    files,
    skipped,
    skip(why) {
      skipped[why] += 1;
    },
    /** The checks before a member of `size` bytes is read; false when it is passed over. */
    admit(rel, size) {
      if (shouldSkip(rel) || !detectLanguage(rel)) skipped.filtered += 1;
      else if (size > LIMITS.maxFileBytes) skipped.too_large += 1;
      else if (stopped || (total += size) > LIMITS.maxTotalBytes) {
        stopped = stopped || "bytes";
        skipped.over_limit += 1;
      } else return true;
      return false;
    },
    add({ file, why }) {
      if (file) files.push(file);
      else skipped[why] += 1;
      if (files.length >= LIMITS.maxFiles) stopped = "files";
    },
    notes() {
      const n = skipped.over_limit;
      if (!n) return [];
      const more = `${n} more supported file${n === 1 ? " was" : "s were"} not scanned`;
      return [stopped === "files"
        ? `Scanned the first ${LIMITS.maxFiles} files; ${more} (scan limit).`
        : `Stopped at ${Math.round(LIMITS.maxTotalBytes / 2 ** 20)} MB of source; ${more} (scan limit).`];
    },
  };
}

const result = (out, name, extra = {}) => ({ files: out.files, name, skipped: out.skipped, notes: out.notes(), ...extra });

/** load_zip's path-traversal check: PurePosixPath(name).is_absolute() or ".." in its parts. */
const unsafe = (name) => name.startsWith("/") || posixParts(name).includes("..");

// ---------------------------------------------------------------------------------------------- files

/** A browser-supplied path as a relative POSIX path: backslashes become "/", leading "./" and "/" are dropped. */
export function normalizePath(path) {
  let p = String(path).replace(/\\/g, "/");
  while (p.startsWith("/") || p.startsWith("./")) p = p.slice(p.startsWith("/") ? 1 : 2);
  return p;
}

/** The path a File was picked or dropped at: react-dropzone's file-selector sets relativePath and path ("./a.js",
 *  "/dir/a.js"), <input webkitdirectory> sets webkitRelativePath ("dir/a.js"), and a loose file has only its name. */
export const filePath = (file) => file.relativePath || file.path || file.webkitRelativePath || file.name;

/** Files picked in the browser, as an upload of them would be read by load_zip (sorted by path, one shared top
 *  folder stripped). Items are File objects, or {file, path} pairs: a structured clone to a worker keeps neither
 *  file-selector's path properties nor webkitRelativePath, so the client captures the path before posting. */
export async function loadFromFiles(fileArray, { name, onProgress = () => {}, signal } = {}) {
  const items = Array.from(fileArray || [], (item) => {
    const file = item.file || item;
    return { file, path: normalizePath(item.file ? item.path || filePath(file) : filePath(file)) };
  }).sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const prefix = stripCommonPrefix(items.map((item) => item.path));
  const out = collector();
  for (const [i, { file, path }] of items.entries()) {
    throwIfAborted(signal);
    const rel = path.slice(prefix.length);
    if (unsafe(rel)) out.skip("filtered");
    else if (out.admit(rel, file.size)) out.add(make(rel, new Uint8Array(await file.arrayBuffer())));
    if (i % 50 === 0) onProgress("Reading files", Math.round((100 * i) / items.length));
  }
  const fallback = items.length === 1 ? stem(items[0].path) : "Local files";
  return result(out, name || (prefix ? prefix.slice(0, -1) : fallback));
}

// ---------------------------------------------------------------------------------------------- ZIP

// A reader for what zipfile.ZipFile does on open and on zf.open(info) (Python 3.12), with only DEFLATE and stored
// members (fflate). Members are read lazily from the Blob, so a large archive is never held in memory.
const EOCD = 0x06054b50;
const EOCD64 = 0x06064b50;
const LOCATOR64 = 0x07064b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;
const CP437 = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ";
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

const u16 = (b, i) => b[i] | (b[i + 1] << 8);
const u32 = (b, i) => (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)) + b[i + 3] * 2 ** 24;
const u64 = (b, i) => u32(b, i) + u32(b, i + 4) * 2 ** 32;

let crcTable;
function crc32(bytes) {
  if (!crcTable) {
    crcTable = new Int32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c;
    }
  }
  let c = -1;
  for (let i = 0; i < bytes.length; i++) c = crcTable[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

const notZip = () => new SourceError("That file isn't a valid ZIP archive.");
const damaged = (entry) => new SourceError(`That ZIP archive is damaged ("${entry.name}" can't be read).`);

/** Member names are UTF-8 when flag bit 11 is set and cp437 otherwise; ZipInfo cuts them at the first NUL. */
function decodeName(raw, flags) {
  if (flags & 0x800) {
    try {
      return UTF8.decode(raw);
    } catch {
      throw notZip();
    }
  }
  let s = "";
  for (const b of raw) s += b < 0x80 ? String.fromCharCode(b) : CP437[b - 0x80];
  return s;
}
const sanitize = (name) => (name.includes("\0") ? name.slice(0, name.indexOf("\0")) : name);

/** read(start, end) over a Blob/File, ArrayBuffer or typed array. */
function byteReader(input) {
  if (input && typeof input.arrayBuffer === "function") {
    return { size: input.size, read: async (a, b) => new Uint8Array(await input.slice(a, b).arrayBuffer()) };
  }
  let bytes;
  if (ArrayBuffer.isView(input)) bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  else if (Object.prototype.toString.call(input) === "[object ArrayBuffer]") bytes = new Uint8Array(input);
  else throw new SourceError("Choose a .zip file to scan.");
  return { size: bytes.length, read: async (a, b) => bytes.subarray(a, b) };
}

/** zipfile._EndRecData and _EndRecData64: where the central directory is and how long it is. */
async function endRecord({ size, read }) {
  if (size < 22) throw notZip();
  const base = Math.max(0, size - 65536 - 22);
  const tail = await read(base, size);
  let at = tail.length - 22;
  if (!(u32(tail, at) === EOCD && tail[at + 20] === 0 && tail[at + 21] === 0)) {
    at = -1;
    for (let i = tail.length - 4; i >= 0 && at < 0; i--) if (u32(tail, i) === EOCD) at = i;
    if (at < 0 || at + 22 > tail.length) throw notZip();
  }
  const end = { size: u32(tail, at + 12), offset: u32(tail, at + 16), location: base + at };
  let offset = end.location - 20;
  if (offset < 0) return end;
  const locator = await read(offset, offset + 20);
  if (u32(locator, 0) !== LOCATOR64) return end;
  const reloff = u64(locator, 8);
  if (u32(locator, 4) !== 0 || u32(locator, 16) > 1) throw notZip(); // multi-disk archive
  offset -= 56;
  if (reloff > offset) throw notZip();
  let extra = offset - reloff;
  let rec = await read(reloff, reloff + 56);
  if (u32(rec, 0) !== EOCD64 && reloff !== offset) {
    rec = await read(offset, offset + 56);
    extra = 0;
  }
  if (rec.length !== 56 || u32(rec, 0) !== EOCD64) throw notZip();
  const dirsize = u64(rec, 40);
  const diroffset = u64(rec, 48);
  if (diroffset + dirsize !== reloff || u64(rec, 4) + 12 !== 56 + extra) throw notZip();
  return { size: dirsize, offset: diroffset, location: offset - extra };
}

/** ZipFile._RealGetContents: the infolist, with zip64 sizes, Unicode path fields and each entry's end offset. */
async function centralDirectory(reader) {
  const end = await endRecord(reader);
  const concat = end.location - end.size - end.offset;
  const startDir = end.offset + concat;
  if (startDir < 0) throw notZip();
  const cd = await reader.read(startDir, startDir + end.size);
  const entries = [];
  for (let pos = 0; pos < end.size;) {
    if (pos + 46 > cd.length || u32(cd, pos) !== CENTRAL) throw notZip();
    const flags = u16(cd, pos + 8);
    const [n, e, c] = [u16(cd, pos + 28), u16(cd, pos + 30), u16(cd, pos + 32)];
    if (cd[pos + 6] > 63) throw new SourceError("That ZIP archive needs a newer unzip tool than the scanner has.");
    const rawName = cd.subarray(pos + 46, pos + 46 + n);
    const orig = decodeName(rawName, flags);
    const entry = {
      name: sanitize(orig), orig, flags, method: u16(cd, pos + 10), crc: u32(cd, pos + 16),
      compressedSize: u32(cd, pos + 20), fileSize: u32(cd, pos + 24), headerOffset: u32(cd, pos + 42),
    };
    // ZipInfo._decodeExtra: zip64 sizes (0x0001) and the Info-ZIP Unicode path (0x7075)
    for (let x = cd.subarray(pos + 46 + n, pos + 46 + n + e); x.length >= 4; x = x.subarray(u16(x, 2) + 4)) {
      if (u16(x, 2) + 4 > x.length) throw notZip();
      const data = x.subarray(4, u16(x, 2) + 4);
      if (u16(x, 0) === 0x0001) {
        let d = 0;
        const next = () => {
          if (d + 8 > data.length) throw notZip();
          d += 8;
          return u64(data, d - 8);
        };
        if (entry.fileSize === 0xffffffff) entry.fileSize = next();
        if (entry.compressedSize === 0xffffffff) entry.compressedSize = next();
        if (entry.headerOffset === 0xffffffff) entry.headerOffset = next();
      } else if (u16(x, 0) === 0x7075) {
        if (data.length < 5) throw notZip();
        if (data[0] === 1 && u32(data, 1) === crc32(rawName)) {
          const unicode = decodeName(data.subarray(5), 0x800);
          if (unicode) entry.name = sanitize(unicode);
        }
      }
    }
    entry.headerOffset += concat;
    entries.push(entry);
    pos += 46 + n + e + c;
  }
  let endOffset = startDir;
  for (const entry of [...entries].sort((a, b) => b.headerOffset - a.headerOffset)) {
    entry.endOffset = endOffset;
    endOffset = entry.headerOffset;
  }
  return entries;
}

/** zf.open(info).read(): the checks Python makes before and after decompressing, and the CRC it verifies. */
async function readMember({ read }, entry) {
  const head = await read(entry.headerOffset, entry.headerOffset + 30);
  if (head.length !== 30 || u32(head, 0) !== LOCAL) throw damaged(entry);
  const start = entry.headerOffset + 30 + u16(head, 26) + u16(head, 28);
  if (entry.flags & 0x60) throw new SourceError(`"${entry.name}" uses a ZIP feature the scanner can't read.`);
  if (decodeName(await read(entry.headerOffset + 30, entry.headerOffset + 30 + u16(head, 26)), u16(head, 6)) !== entry.orig) {
    throw damaged(entry);
  }
  if (start + entry.compressedSize > entry.endOffset) {
    throw new SourceError("That ZIP archive has overlapping entries (a possible zip bomb), so it wasn't scanned.");
  }
  if (entry.flags & 1) throw new SourceError(`"${entry.name}" is encrypted; password-protected ZIPs can't be scanned.`);
  if (entry.method !== 0 && entry.method !== 8) {
    throw new SourceError(`"${entry.name}" uses a compression method the browser scanner can't read `
      + `(method ${entry.method}). Re-create the ZIP with standard Deflate compression.`);
  }
  // ZipExtFile yields at most file_size bytes, accepts a stream that ends sooner, and checks the CRC of what it
  // yielded; it fails when the archive runs out of compressed bytes first.
  const data = await read(start, start + entry.compressedSize);
  let bytes;
  if (entry.method === 0) {
    if (data.length < Math.min(entry.compressedSize, entry.fileSize)) throw damaged(entry);
    bytes = data.subarray(0, entry.fileSize);
  } else if (!entry.compressedSize) bytes = data;
  else {
    if (!data.length) throw damaged(entry);
    // A fixed output buffer caps memory at the declared size however far the stream inflates: fflate drops the rest.
    try {
      bytes = inflateSync(data, { out: new Uint8Array(entry.fileSize) });
    } catch {
      throw damaged(entry);
    }
  }
  if (crc32(bytes) !== entry.crc) throw damaged(entry);
  return bytes;
}

/** sources.load_zip for a File, Blob, ArrayBuffer or Uint8Array. */
export async function loadFromZip(input, { name, onProgress = () => {}, signal } = {}) {
  const reader = byteReader(input);
  const entries = await centralDirectory(reader);
  if (entries.length > LIMITS.maxMembers) throw new SourceError(`Archive has too many entries (${entries.length}).`);
  const isDir = (entry) => entry.name.endsWith("/");
  const prefix = stripCommonPrefix(entries.filter((entry) => !isDir(entry)).map((entry) => entry.name));
  const out = collector();
  for (const [i, entry] of entries.entries()) {
    throwIfAborted(signal);
    if (isDir(entry)) continue;
    if (entry.name.startsWith(LIMITS.zipJunk) || unsafe(entry.name)) {
      out.skip("filtered");
      continue;
    }
    const rel = prefix && entry.name.startsWith(prefix) ? entry.name.slice(prefix.length) : entry.name;
    if (out.admit(rel, entry.fileSize)) out.add(make(rel, await readMember(reader, entry)));
    if (i % 50 === 0) onProgress("Unpacking ZIP", Math.round((100 * i) / entries.length));
  }
  return result(out, name || (typeof input?.name === "string" && input.name ? stem(input.name) : "archive"));
}

// ---------------------------------------------------------------------------------------------- GitHub

// The server downloads the zipball, but codeload.github.com only allows render.githubusercontent.com as a CORS
// origin, so the browser lists the commit's tree (api.github.com, CORS *) and fetches each file. Public files come
// from raw.githubusercontent.com, which sends CORS * and does not count against the API quota, but answers every
// CORS preflight with 403: a request carrying Authorization fails there, so a token is sent to api.github.com only
// and a private repository's files come from the git blobs API (raw media type) instead.
const API = "https://api.github.com";
const RAW = "https://raw.githubusercontent.com";
const CONCURRENCY = 8;
const enc = (path) => path.split("/").map(encodeURIComponent).join("/");

/** 12:34 local time for an X-RateLimit-Reset epoch. */
export const resetClock = (epochSeconds) =>
  new Date(epochSeconds * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

async function githubError(res, token, notFound) {
  const body = await Promise.resolve().then(() => res.json()).catch(() => null);
  const message = typeof body?.message === "string" ? body.message : "";
  const reset = Number(res.headers.get("x-ratelimit-reset"));
  const retryAfter = Number(res.headers.get("retry-after"));
  if (res.status === 401) {
    return new SourceError("GitHub rejected the token (401 Bad credentials). Check it, or clear it to scan a public repository.");
  }
  if ((res.status === 403 || res.status === 429) && res.headers.get("x-ratelimit-remaining") === "0") {
    const when = reset > 0
      ? ` It resets at ${resetClock(reset)} (in ${Math.max(1, Math.ceil((reset * 1000 - Date.now()) / 60000))} min).`
      : "";
    return new SourceError(token
      ? `GitHub's API rate limit for this token is used up.${when}`
      : `GitHub's API rate limit for requests without a token (60 an hour) is used up.${when} `
        + "Add a GitHub token to raise it to 5,000 an hour.");
  }
  if ((res.status === 403 || res.status === 429) && (retryAfter > 0 || /rate limit/i.test(message))) {
    return new SourceError(`GitHub is throttling requests. Try again in ${retryAfter > 0 ? retryAfter : 60} seconds.`);
  }
  if (res.status === 404 && notFound) return new SourceError(notFound);
  return new SourceError(`GitHub answered HTTP ${res.status}${message ? ` (${message})` : ""}.`);
}

async function send(fetchImpl, url, init, host) {
  try {
    return await fetchImpl(url, init);
  } catch (err) {
    if (err?.name === "AbortError") throw abortError();
    throw new SourceError(`Couldn't reach ${host}. Check your connection and try again.`);
  }
}

/** Load results[i] = await load(items[i]) with bounded concurrency, stopping once `limit` loaded items in order
 *  carry a file (load_zip's MAX_FILES break, in tree order whatever order the downloads finish in). Downloads run
 *  at most WINDOW items ahead of the first unfinished one, so a slow file near the limit cannot let the others
 *  fetch an unbounded number of files that would be thrown away. */
const WINDOW = 2 * CONCURRENCY;
async function inOrder(items, load, limit, onSettled) {
  const results = [];
  let next = 0;
  let end = items.length;
  let settled = 0; // results[0..settled) are all in
  let accepted = 0;
  let done = 0;
  let failed = false;
  const waiting = [];
  const wake = () => waiting.splice(0).forEach((resolve) => resolve());
  const pump = async () => {
    while (next < end && !failed) {
      if (next - settled >= WINDOW) {
        await new Promise((resolve) => waiting.push(resolve));
        continue;
      }
      const i = next++;
      try {
        results[i] = await load(items[i]);
      } catch (err) {
        failed = true;
        wake();
        throw err;
      }
      for (; settled < end && results[settled]; settled++) {
        if (results[settled].file && ++accepted >= limit) end = settled + 1;
      }
      wake();
      onSettled(++done);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, items.length) }, pump));
  return results.slice(0, end);
}

/** sources.load_github without the zipball: repo meta, the commit, its recursive tree, then each file. */
export async function loadFromGitHub(url, { token, fetchImpl, onProgress = () => {}, signal } = {}) {
  const parsed = parseGithubUrl(String(url ?? ""));
  if (!parsed) throw new SourceError("Enter a repository URL like https://github.com/owner/repo");
  const [owner, repo, urlRef] = parsed;
  const http = fetchImpl || ((...args) => globalThis.fetch(...args));
  const base = `${API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  const auth = token ? { Authorization: `Bearer ${token}` } : {};
  const api = (path, accept = "application/vnd.github+json") =>
    send(http, `${base}${path}`, { headers: { Accept: accept, ...auth }, signal }, "api.github.com");

  onProgress("Fetching repository info", 2);
  const metaRes = await api("");
  if (!metaRes.ok) {
    throw await githubError(metaRes, token, token
      ? `Repository ${owner}/${repo} not found, or the token can't read it.`
      : `Repository ${owner}/${repo} not found. It must be public, or add a GitHub token that can read it.`);
  }
  const info = await metaRes.json();
  const ref = urlRef || info.default_branch || "main";

  let sha = /^[0-9a-f]{40}$/i.test(ref) ? ref.toLowerCase() : null;
  if (!sha) {
    const res = await api(`/commits/${enc(ref)}`, "application/vnd.github.sha");
    if (res.status === 409) throw new SourceError(`${owner}/${repo} is empty.`);
    if (res.status === 404 || res.status === 422) {
      throw new SourceError(`Couldn't find branch, tag or commit "${ref}" in ${owner}/${repo}. Link to the `
        + "repository or a branch (https://github.com/owner/repo/tree/branch), not to a folder or file in it.");
    }
    if (!res.ok) throw await githubError(res, token);
    sha = pyStrip(await res.text());
    if (!/^[0-9a-f]{40}$/.test(sha)) throw new SourceError(`GitHub returned no commit for "${ref}".`);
  }

  onProgress("Listing files", 6);
  const treeRes = await api(`/git/trees/${sha}?recursive=1`);
  if (!treeRes.ok) throw await githubError(treeRes, token, `Couldn't list the files of ${owner}/${repo} at ${ref}.`);
  const tree = await treeRes.json();

  // Tree order is git's, the order git archive writes the zipball in, so the files and the limits match the
  // server's; tree paths are already repo-relative (no `owner-repo-sha/` wrapper to strip). Submodules (type
  // "commit") are not in a zipball, and symlinks (mode 120000) are passed over rather than followed.
  const out = collector();
  const candidates = [];
  for (const entry of tree.tree || []) {
    if (entry.type !== "blob") continue;
    if (entry.mode === "120000") out.skip("filtered");
    else if (out.admit(entry.path, Number(entry.size) || 0)) candidates.push(entry);
  }

  const viaApi = Boolean(info.private);
  const download = async (entry) => {
    const target = viaApi ? `${base}/git/blobs/${entry.sha}` : `${RAW}/${enc(owner)}/${enc(repo)}/${sha}/${enc(entry.path)}`;
    const init = viaApi ? { headers: { Accept: "application/vnd.github.raw+json", ...auth }, signal } : { signal };
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await send(http, target, init, viaApi ? "api.github.com" : "raw.githubusercontent.com");
      } catch (err) {
        if (err.name === "AbortError" || attempt) throw err;
        continue; // one retry for a dropped connection
      }
      if (res.ok) return make(entry.path, new Uint8Array(await res.arrayBuffer()));
      if (res.status >= 500 && !attempt) continue;
      if (viaApi) throw await githubError(res, token, `Couldn't download ${entry.path} from GitHub.`);
      if (res.status === 403 || res.status === 429) {
        throw new SourceError("raw.githubusercontent.com is rate-limiting downloads. Wait a few minutes and try again.");
      }
      throw new SourceError(`Couldn't download ${entry.path} from GitHub (HTTP ${res.status}).`);
    }
  };
  const loaded = await inOrder(candidates, download, LIMITS.maxFiles, (done) =>
    onProgress(`Downloading files (${done}/${candidates.length})`, 10 + Math.round((90 * done) / candidates.length)));
  loaded.forEach((r) => out.add(r));
  for (let i = loaded.length; i < candidates.length; i++) out.skip("over_limit");

  const repoMeta = {
    owner, repo, ref, sha, url: info.html_url || `https://github.com/${owner}/${repo}`,
    stars: info.stargazers_count ?? null, description: info.description ?? null, language: info.language ?? null,
    private: viaApi,
  };
  const loadResult = result(out, `${owner}/${repo}`, { repo_meta: repoMeta });
  if (tree.truncated) {
    loadResult.notes.unshift("GitHub listed only part of this very large repository, so some files were not "
      + "scanned. Scan a ZIP or folder of it for full coverage.");
  }
  return loadResult;
}

// ---------------------------------------------------------------------------------------------- dispatch

/** Load the source a scan job names: {kind: "github" | "zip" | "files", input, name, token}. */
export function loadSource({ kind, input, name, token }, options = {}) {
  if (kind === "github") return loadFromGitHub(input, { ...options, token });
  if (kind === "zip") return loadFromZip(input, { ...options, name });
  if (kind === "files") return loadFromFiles(input, { ...options, name });
  return Promise.reject(new SourceError(`Unknown source kind "${kind}".`));
}
