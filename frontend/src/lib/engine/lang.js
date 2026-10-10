// Source loading semantics for the in-browser engine: a port of backend/codeguard/sources.py driven by
// rules.generated.json (generated from the Python engine, never edited by hand), plus the Python string and number
// semantics the engine ports rely on. Python counts code points and rounds half to even; JS counts UTF-16 units and
// rounds ties away from zero, so every port goes through these helpers. Vectors: parity.golden.json, lang.test.js.
import RULES from "./rules.generated.json";

export { RULES };

const S = RULES.sources;
const own = (obj, key) => Object.prototype.hasOwnProperty.call(obj, key);
const fromCps = (cps) => new Set(cps.map((cp) => String.fromCodePoint(cp)));
const WHITESPACE = fromCps(RULES.python.whitespace); // all BMP, so code-unit scans are safe
const LINE_BREAKS = fromCps(RULES.python.line_breaks);
const REPLACEMENT = String.fromCharCode(0xfffd);
const SURROGATES = /[\ud800-\udfff]/;

// ---------------------------------------------------------------------------------------------- regexes

const compiled = new Map();

/** RegExp for a spec from rules.generated.json. Pass extra "g" where Python uses findall/finditer/sub/split;
 *  global regexes are never cached, so their lastIndex state is never shared. */
export function compileRegex(spec, extra = "") {
  if (extra) return new RegExp(spec.pattern, spec.flags + extra);
  let re = compiled.get(spec);
  if (!re) {
    re = new RegExp(spec.pattern, spec.flags);
    compiled.set(spec, re);
  }
  return re;
}

/** Every regex spec in the rules as [key, spec], keyed like browser_export.iter_regexes (list items by id). */
export function regexSpecs(node = RULES, path = "") {
  const out = [];
  if (Array.isArray(node)) {
    node.forEach((v, i) => out.push(...regexSpecs(v, `${path}.${v && typeof v === "object" && "id" in v ? v.id : i}`)));
  } else if (node && typeof node === "object") {
    if ("pattern" in node && "flags" in node) out.push([path, node]);
    Object.entries(node).forEach(([k, v]) => {
      if (k !== "python") out.push(...regexSpecs(v, path ? `${path}.${k}` : k));
    });
  }
  return out;
}

// ------------------------------------------------------------------------------------ Python str semantics

/** len(s): code points, not UTF-16 units. */
export function pyLen(s) {
  let n = s.length;
  for (let i = 0; i < s.length - 1; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) { n -= 1; i += 1; }
    }
  }
  return n;
}

/** s[start:end] over code points, with Python's negative and out-of-range indexes. */
export function pySlice(s, start = 0, end = null) {
  const chars = SURROGATES.test(s) ? Array.from(s) : null;
  const n = chars ? chars.length : s.length;
  const at = (i, dflt) => (i == null ? dflt : i < 0 ? Math.max(0, n + i) : Math.min(i, n));
  const a = at(start, 0);
  const b = at(end, n);
  if (b <= a) return "";
  return chars ? chars.slice(a, b).join("") : s.slice(a, b);
}

/** Code-unit offset in s of code-point offset cp (for mapping between Python and JS match positions). */
export function cpToIndex(s, cp) {
  let i = 0;
  for (let k = 0; k < cp && i < s.length; k++) i += s.codePointAt(i) > 0xffff ? 2 : 1;
  return i;
}

/** Code-point offset of code-unit offset index in s. */
export const indexToCp = (s, index) => pyLen(s.slice(0, index));

export function pyLstrip(s) {
  let i = 0;
  while (i < s.length && WHITESPACE.has(s[i])) i++;
  return s.slice(i);
}

export function pyRstrip(s) {
  let j = s.length;
  while (j > 0 && WHITESPACE.has(s[j - 1])) j--;
  return s.slice(0, j);
}

/** str.strip(): Python's whitespace set differs from String.prototype.trim (U+001C-U+001F, U+0085 vs U+FEFF). */
export const pyStrip = (s) => pyRstrip(pyLstrip(s));

/** str.split() with no separator: runs of whitespace, no empty strings. */
export function pySplit(s) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= s.length; i++) {
    const ws = i === s.length || WHITESPACE.has(s[i]);
    if (ws && start >= 0) { out.push(s.slice(start, i)); start = -1; } else if (!ws && start < 0) start = i;
  }
  return out;
}

/** str.splitlines(): also breaks on VT, FF, U+001C-U+001E, U+0085, U+2028, U+2029; CR LF is one break. */
export function pySplitLines(s) {
  const out = [];
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (!LINE_BREAKS.has(s[i])) continue;
    out.push(s.slice(start, i));
    if (s[i] === "\r" && s[i + 1] === "\n") i += 1;
    start = i + 1;
  }
  if (start < s.length) out.push(s.slice(start));
  return out;
}

// ---------------------------------------------------------------------------------- Python number semantics

/** f"{x:.{digits}f}" for |x| < 1e21. Both round the exact binary value, but on an exact tie toFixed goes away
 *  from zero and Python to even. x is such a tie exactly when x * 2^(digits+1) is an odd integer; then an odd last
 *  digit steps back by one (never a borrow, since it is odd). */
export function pyFixed(x, digits) {
  const s = Object.is(x, -0) ? `-${x.toFixed(digits)}` : x.toFixed(digits);
  const scaled = Math.abs(x) * 2 ** (digits + 1);
  if (!Number.isInteger(scaled) || scaled % 2 === 0) return s;
  const last = s.charCodeAt(s.length - 1) - 48;
  return last % 2 ? s.slice(0, -1) + (last - 1) : s;
}

/** round(x, digits) for digits >= 1: Python rounds the exact binary value half to even. */
export const pyRound = (x, digits) => Number(pyFixed(x, digits));

/** sum() of floats as CPython 3.12+ computes it (Neumaier compensation); exact for integers. */
export function pySum(xs) {
  let total = 0;
  let c = 0;
  for (const x of xs) {
    const t = total + x;
    c += Math.abs(total) >= Math.abs(x) ? total - t + x : x - t + total;
    total = t;
  }
  return c && Number.isFinite(c) ? total + c : total;
}

// ------------------------------------------------------------------------------------------------ paths

/** PurePosixPath(path).parts: empty and "." segments dropped, a leading "/" (or exactly "//") kept as root. */
export function posixParts(path) {
  const rest = path.split("/").filter((p) => p && p !== ".");
  if (!path.startsWith("/")) return rest;
  return [path.startsWith("//") && !path.startsWith("///") ? "//" : "/", ...rest];
}

/** PurePosixPath(path).name */
export function baseName(path) {
  const parts = posixParts(path);
  const last = parts.length ? parts[parts.length - 1] : "";
  return last.startsWith("/") ? "" : last;
}

/** PurePosixPath(path).suffix: the last ".ext", unless the dot leads or ends the name. */
export function suffixOf(path) {
  const name = baseName(path);
  const i = name.lastIndexOf(".");
  return i > 0 && i < name.length - 1 ? name.slice(i) : "";
}

const REQUIREMENTS_FILE = compileRegex(S.requirements_file);
const SKIP_DIRS = new Set(S.skip_dirs);
const SKIP_FILES = new Set(S.skip_files);
const NON_CODE = new Set(S.non_code);

/** sources.detect_language: the engine language for a path, or null when the file is not scanned. */
export function detectLanguage(path) {
  const name = baseName(path).toLowerCase();
  if (own(S.special_names, name)) return S.special_names[name];
  if (name.startsWith(S.env_prefix) || REQUIREMENTS_FILE.test(name)) return "config";
  if (S.unscanned_suffixes.some((suffix) => name.endsWith(suffix))) return null;
  const suffix = suffixOf(path).toLowerCase();
  return own(S.languages, suffix) ? S.languages[suffix] : null;
}

/** sources.should_skip: lockfiles and anything under a vendored / generated directory. Case-sensitive, as in Python. */
export function shouldSkip(path) {
  const parts = posixParts(path);
  return SKIP_FILES.has(baseName(path)) || parts.slice(0, -1).some((part) => SKIP_DIRS.has(part));
}

/** sources.iter_code: json/config files are scanned for secrets and manifests but not measured as code. */
export const isCode = (file) => !NON_CODE.has(file.language);

/** sources._strip_common_prefix: GitHub zipballs wrap everything in one `owner-repo-sha/` folder. */
export function stripCommonPrefix(paths) {
  const tops = new Set(paths.filter((p) => p.includes("/")).map((p) => p.split("/", 1)[0]));
  return tops.size === 1 && paths.every((p) => p.includes("/")) ? `${[...tops][0]}/` : "";
}

const GITHUB_URL = compileRegex(S.github_url);

/** sources.parse_github_url: [owner, repo, ref or null], or null for anything that is not a GitHub repo URL. */
export function parseGithubUrl(url) {
  const m = GITHUB_URL.exec(pyStrip(url));
  return m ? [m[2], m[3], m[6] ?? null] : null;
}

// ---------------------------------------------------------------------------------------------- content

/** bytes.decode("utf-8", errors="ignore"). TextDecoder replaces malformed bytes with U+FFFD where Python drops
 *  them; a genuine U+FFFD (EF BF BD) can never be part of a malformed sequence, so the runs between genuine ones
 *  are decoded separately and every U+FFFD they produce is dropped. A leading BOM is kept, as in Python. */
export function decodeUtf8(bytes) {
  const decoder = new TextDecoder("utf-8", { ignoreBOM: true });
  const clean = (chunk) => decoder.decode(chunk).split(REPLACEMENT).join("");
  const out = [];
  let start = 0;
  for (let i = 0; i + 2 < bytes.length; i++) {
    if (bytes[i] === 0xef && bytes[i + 1] === 0xbf && bytes[i + 2] === 0xbd) {
      out.push(clean(bytes.subarray(start, i)), REPLACEMENT);
      start = i + 3;
      i += 2;
    }
  }
  out.push(clean(bytes.subarray(start)));
  return out.join("");
}

/** "\x00" in text[:n], counting code points. */
function nulWithin(text, n) {
  for (let i = 0, cps = 0; i < text.length && cps < n; i++, cps++) {
    const c = text.charCodeAt(i);
    if (c === 0) return true;
    if (c >= 0xd800 && c <= 0xdbff && i + 1 < text.length) {
      const d = text.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) i += 1;
    }
  }
  return false;
}

/** sources._make for already-decoded text: {path, content, language, lines}, or null for unscanned and binary
 *  files. Like Python it does not apply shouldSkip or the size limits; loaders do that first. */
export function makeSourceFile(path, content) {
  const language = detectLanguage(path);
  if (!language || nulWithin(content, S.binary_sniff)) return null;
  return { path, content, language, lines: content.split("\n").length };
}

/** sources._make: decode raw bytes the way Python does, then makeSourceFile. */
export const sourceFileFromBytes = (path, bytes) => makeSourceFile(path, decodeUtf8(bytes));

/** Loader limits shared with the server (sources.py). */
export const LIMITS = {
  maxFiles: S.max_files,
  maxFileBytes: S.max_file_bytes,
  maxTotalBytes: S.max_total_bytes,
  maxMembers: S.max_members,
  maxDownloadBytes: S.max_download_bytes,
  zipJunk: S.zip_junk,
};
