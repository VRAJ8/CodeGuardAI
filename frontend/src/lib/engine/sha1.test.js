/** @jest-environment node */
import { createHash } from "crypto";
import GOLDEN from "./parity.golden.json";
import { fingerprint, sha1Bytes, sha1Hex, utf8, withFingerprint } from "./sha1";

const F = GOLDEN.vectors.fingerprints;

describe("sha1", () => {
  test("FIPS 180 test vectors", () => {
    expect(sha1Hex("")).toBe("da39a3ee5e6b4b0d3255bfef95601890afd80709");
    expect(sha1Hex("abc")).toBe("a9993e364706816aba3e25717850c26c9cd0d89d");
    expect(sha1Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe("84983e441c3bd26ebaae4aa1f95129e5e54670f1");
    expect(sha1Hex("a".repeat(1000000))).toBe("34aa973cd4c4daa4f61eeb2bdbad27316534016f");
  });

  test("agrees with node:crypto on every padding boundary and on random Unicode", () => {
    const bad = [];
    for (let n = 0; n < 200; n++) {
      const bytes = Array.from({ length: n }, (_, i) => (i * 131 + n) & 255);
      const want = createHash("sha1").update(Buffer.from(bytes)).digest("hex");
      if (sha1Bytes(bytes) !== want) bad.push(n);
    }
    let seed = 7;
    const rand = () => { seed = (seed * 48271) % 2147483647; return seed; };
    for (let k = 0; k < 300; k++) {
      const cps = Array.from({ length: rand() % 40 }, () => [rand() % 0x80, rand() % 0x800, rand() % 0xd800, 0x10000 + (rand() % 0xfffff)][rand() % 4]);
      const text = String.fromCodePoint(...cps);
      if (sha1Hex(text) !== createHash("sha1").update(text, "utf8").digest("hex")) bad.push(text);
    }
    expect(bad).toEqual([]);
  });

  test("utf8 matches TextEncoder, lone surrogates included", () => {
    const text = `aé€${String.fromCodePoint(0x1f600)}\ud800z`;
    expect(utf8(text)).toEqual([...new TextEncoder().encode(text)]);
  });
});

describe("fingerprints", () => {
  test("Finding.with_fingerprint(source_line) vectors", () => {
    const got = F.cases.map((c) => withFingerprint({ rule_id: c.rule_id, file_path: c.file_path, line_number: c.line_number, snippet: c.snippet,
      fp_basis: null }, c.source_line).fingerprint);
    expect(got).toEqual(F.cases.map((c) => c.fingerprint));
  });

  test("fp_basis beats the source line, which beats the snippet; no code at all uses the line number", () => {
    const f = { rule_id: "R", file_path: "a.js", line_number: 4, snippet: "snip", fp_basis: "masked <secret>" };
    expect(withFingerprint({ ...f }, "src").fingerprint).toBe(fingerprint("R", "a.js", 4, "masked <secret>"));
    expect(withFingerprint({ ...f, fp_basis: null }, "src").fingerprint).toBe(fingerprint("R", "a.js", 4, "src"));
    expect(withFingerprint({ ...f, fp_basis: null }).fingerprint).toBe(fingerprint("R", "a.js", 4, "snip"));
    expect(fingerprint("R", "a.js", 4, "  ")).toBe(sha1Hex("v2|R|a.js|line:4").slice(0, 16));
    expect(fingerprint("R", "a.js", null, null)).toBe(sha1Hex("v2|R|a.js|line:None").slice(0, 16)); // Python's f"{None}"
  });
});
