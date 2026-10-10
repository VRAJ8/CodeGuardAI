// SHA-1 and the finding fingerprints built on it (models.Finding.with_fingerprint). Synchronous and dependency-free,
// so it runs the same in the page, a worker and jest; SubtleCrypto is async-only and absent outside secure contexts.
import { RULES, compileRegex, pySplit } from "./lang";

/** str.encode("utf-8"). Python raises on a lone surrogate; here it becomes U+FFFD, as TextEncoder does. */
export function utf8(text) {
  const out = [];
  for (const ch of text) {
    let cp = ch.codePointAt(0);
    if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
  }
  return out;
}

const rotl = (x, n) => (x << n) | (x >>> (32 - n));

/** Lowercase hex SHA-1 digest of a byte array (FIPS 180-4). */
export function sha1Bytes(bytes) {
  const n = bytes.length;
  const words = new Int32Array(Math.ceil((n + 9) / 64) * 16); // big-endian message words, padded
  for (let i = 0; i < n; i++) words[i >> 2] |= bytes[i] << (24 - (i & 3) * 8);
  words[n >> 2] |= 0x80 << (24 - (n & 3) * 8);
  words[words.length - 2] = Math.floor(n / 0x20000000); // bit length, high word
  words[words.length - 1] = n * 8; // low word (Int32Array wraps modulo 2^32)
  const h = [0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476, 0xc3d2e1f0 | 0];
  const w = new Int32Array(80);
  for (let block = 0; block < words.length; block += 16) {
    for (let t = 0; t < 16; t++) w[t] = words[block + t];
    for (let t = 16; t < 80; t++) w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    let [a, b, c, d, e] = h;
    for (let t = 0; t < 80; t++) {
      let f, k;
      if (t < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc | 0; }
      else { f = b ^ c ^ d; k = 0xca62c1d6 | 0; }
      const next = (rotl(a, 5) + f + e + k + w[t]) | 0; // the sum stays below 2^53, so |0 reduces it exactly
      e = d; d = c; c = rotl(b, 30); b = a; a = next;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0; h[4] = (h[4] + e) | 0;
  }
  return h.map((x) => (x >>> 0).toString(16).padStart(8, "0")).join("");
}

/** hashlib.sha1(text.encode()).hexdigest() */
export const sha1Hex = (text) => sha1Bytes(utf8(text));

// ---------------------------------------------------------------------------------------------- fingerprints

const SUPPRESSION_TAIL = compileRegex(RULES.fingerprint.suppression_tail, "g");

/** The 16-hex identity of a finding: rule + file + the normalized flagged code (a trailing codeguard-ignore comment
 *  and whitespace runs do not count), or the line number when there is no code at all. */
export function fingerprint(ruleId, filePath, lineNumber, basis) {
  const code = pySplit((basis || "").replace(SUPPRESSION_TAIL, "")).join(" ");
  return sha1Hex(`v2|${ruleId}|${filePath}|${code || `line:${lineNumber ?? "None"}`}`).slice(0, 16);
}

/** Finding.with_fingerprint(source_line): fp_basis (secrets: the line with the credential masked) wins, then the
 *  source line, then the snippet. Scanners call it without the source; the engine recomputes it from the file. */
export function withFingerprint(finding, sourceLine = null) {
  const basis = finding.fp_basis ?? sourceLine ?? finding.snippet;
  finding.fingerprint = fingerprint(finding.rule_id, finding.file_path, finding.line_number, basis);
  return finding;
}
