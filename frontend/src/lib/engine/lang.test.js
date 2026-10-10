/** @jest-environment node */
// Holds lang.js to the Python engine: every vector comes from parity.golden.json (python -m codeguard.browser_export).
import GOLDEN from "./parity.golden.json";
import {
  RULES, compileRegex, cpToIndex, decodeUtf8, detectLanguage, indexToCp, isCode, makeSourceFile, parseGithubUrl,
  pyFixed, pyLen, pyLstrip, pyRound, pyRstrip, pySlice, pySplit, pySplitLines, pyStrip, pySum, regexSpecs, shouldSkip,
  sourceFileFromBytes, stripCommonPrefix,
} from "./lang";

const V = GOLDEN.vectors;
const join = (runs) => runs.map(([piece, n]) => piece.repeat(n)).join("");
const substitute = (text) =>
  Object.entries(GOLDEN.placeholders).reduce((t, [name, parts]) => t.split(name).join(parts.join("")), text);

/** The cases where fn(input) differs from the expected value, so a failure names the inputs. */
const mismatches = (cases, fn) =>
  cases.flatMap(([input, want]) => {
    const got = fn(input);
    return JSON.stringify(got) === JSON.stringify(want) ? [] : [{ input, want, got }];
  });

describe("sources", () => {
  test("detectLanguage and shouldSkip match sources.py", () => {
    expect(mismatches(V.sources.paths.map((v) => [v.path, [v.language, v.skip]]), (p) => [detectLanguage(p), shouldSkip(p)])).toEqual([]);
  });

  test("stripCommonPrefix", () => {
    expect(mismatches(V.sources.strip_common_prefix.map((v) => [v.paths, v.prefix]), stripCommonPrefix)).toEqual([]);
  });

  test("makeSourceFile counts lines and sniffs NULs like sources._make", () => {
    const cases = V.sources.make_source_file.map((v) => [
      [v.path, join(v.content)], v.file && { ...v.file, content: join(v.file.content) }]);
    expect(mismatches(cases, ([path, content]) => makeSourceFile(path, content))).toEqual([]);
  });

  test("decodeUtf8 drops malformed bytes like errors='ignore'", () => {
    expect(mismatches(V.sources.decode_utf8.map((v) => [v.bytes, v.text]), (b) => decodeUtf8(Uint8Array.from(b)))).toEqual([]);
  });

  test("parseGithubUrl", () => {
    expect(mismatches(V.sources.github_url.map((v) => [v.url, v.parsed]), parseGithubUrl)).toEqual([]);
  });

  test("isCode leaves json and config out", () => {
    expect([isCode({ language: "python" }), isCode({ language: "json" }), isCode({ language: "config" })]).toEqual([true, false, false]);
  });

  test("loading the corpus yields exactly the files Python scans", () => {
    const encoder = new TextEncoder();
    const files = Object.entries(GOLDEN.corpus)
      .filter(([path]) => !shouldSkip(path) && detectLanguage(path))
      .map(([path, content]) => sourceFileFromBytes(path, encoder.encode(substitute(content))))
      .filter(Boolean);
    expect(files.map(({ path, language, lines }) => ({ path, language, lines }))).toEqual(GOLDEN.expected.files);
  });
});

describe("Python semantics", () => {
  test("str helpers", () => {
    const P = V.python.strings;
    expect(mismatches(P.map((v) => [v.s, [v.strip, v.lstrip, v.rstrip, v.split, v.splitlines, v.len]]),
      (s) => [pyStrip(s), pyLstrip(s), pyRstrip(s), pySplit(s), pySplitLines(s), pyLen(s)])).toEqual([]);
  });

  test("slicing and offsets count code points", () => {
    expect(mismatches(V.python.slices.map((v) => [[v.s, v.start, v.end], v.result]), ([s, a, b]) => pySlice(s, a, b))).toEqual([]);
    const s = `a${String.fromCodePoint(0x1f600)}b`;
    expect([cpToIndex(s, 2), indexToCp(s, 3), cpToIndex(s, 9)]).toEqual([3, 2, 4]);
  });

  test("pyFixed and pyRound round exact ties to even", () => {
    expect(mismatches(V.python.fixed.map((v) => [[v.x, v.digits], v.text]), ([x, d]) => pyFixed(x, d))).toEqual([]);
    expect(mismatches(V.python.round.map((v) => [[v.x, v.digits], v.result]), ([x, d]) => pyRound(x, d))).toEqual([]);
    expect([pyFixed(-0.25, 1), pyFixed(-0.5, 0), pyFixed(-0, 2)]).toEqual(["-0.2", "-0", "-0.00"]);
  });

  test("pySum is CPython 3.12's compensated sum", () => {
    expect(mismatches(V.python.sum.map((v) => [v.items, v.neumaier]), pySum)).toEqual([]);
  });
});

describe("rules.generated.json regexes", () => {
  const specs = regexSpecs();

  test("every spec compiles, with and without the global flag", () => {
    expect(specs.length).toBeGreaterThan(50);
    specs.forEach(([, spec]) => {
      expect(compileRegex(spec)).toBeInstanceOf(RegExp);
      expect(compileRegex(spec, "g").flags).toBe("gu");
    });
  });

  test("the golden covers exactly the specs in the rules", () => {
    expect(specs.map(([key]) => key).sort()).toEqual(Object.keys(V.regex.results).sort());
  });

  test("every spec matches the probes exactly as Python does", () => {
    const bad = [];
    specs.forEach(([key, spec]) => {
      const re = compileRegex(spec);
      V.regex.probes.forEach((s, i) => {
        const m = re.exec(s);
        const got = m && [indexToCp(s, m.index), indexToCp(s, m.index + m[0].length), m.slice(1).map((g) => g ?? null)];
        const want = V.regex.results[key][i] ?? null;
        if (JSON.stringify(got) !== JSON.stringify(want)) bad.push({ key, probe: s, want, got });
      });
    });
    expect(bad).toEqual([]);
  });

  test("the rules carry the engine version the browser reports", () => {
    expect(RULES.engine.engine_version).toBe(`browser-${GOLDEN.version}`);
    expect(GOLDEN.scan_options.scanners_run).toEqual(RULES.engine.scanners_run);
  });
});
