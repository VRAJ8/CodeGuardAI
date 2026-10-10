// Inline `codeguard-ignore` suppressions, ported from backend/codeguard/suppressions.py. A suppression mechanism in a
// security tool must fail closed: a marker counts only directly after a comment leader, outside string literals and
// as a whole word; anything malformed after it is reported as a warning and never widened into a suppress-all.
// Suppressed findings are kept with a `suppression` record and stay out of the score, counts and gates.
import { RULES, compileRegex, pyLen, pyRstrip, pyStrip } from "./lang";
import { globalRegex } from "./regex";

const S = RULES.suppressions;
const TOKEN = globalRegex(S.token);
const TAIL = compileRegex(S.tail);
const ESCAPED = globalRegex(S.escaped);
const LEADER_PREFIX = new Set(S.leader_prefix);

const count = (text, sub) => text.split(sub).length - 1; // str.count: non-overlapping, left to right

/** An odd number of unescaped quotes before the comment leader means we're inside a literal. */
function inString(prefix) {
  const unescaped = prefix.replace(ESCAPED, "");
  return S.quotes.some((q) => count(unescaped, q) % 2);
}

/** 1-based numbers of lines that start inside a multi-line string (Python triple quotes, JS template literals). */
function multilineStringLines(lines, language) {
  const inside = new Set();
  const delims = Object.prototype.hasOwnProperty.call(S.multiline_delims, language) ? S.multiline_delims[language] : null;
  if (!delims) return inside;
  let open = null;
  lines.forEach((line, i) => {
    if (open) inside.add(i + 1);
    const text = line.replace(ESCAPED, "");
    delims.forEach((d) => {
      if (open && d !== open) return;
      if (count(text, d) % 2) open = open ? null : d;
    });
  });
  return inside;
}

function stripCloser(tail) {
  const text = pyRstrip(tail);
  const closer = S.closers.find((c) => text.endsWith(c));
  return closer ? pyRstrip(text.slice(0, -closer.length)) : text;
}

/** suppressions.parse: {byLine: Map(line -> [{rules: Set, marker_line, justification}]), warnings}. */
export function parseSuppressions(content, path = "", language = "") {
  const out = { byLine: new Map(), warnings: [] };
  if (!content.includes(S.marker)) return out;
  const lines = content.split("\r\n").join("\n").split("\r").join("\n").split("\n");
  const inMultiline = multilineStringLines(lines, language);
  lines.forEach((line, i) => {
    const lineno = i + 1;
    if (inMultiline.has(lineno) || pyLen(line) > S.max_marker_line || !line.includes(S.marker)) return;
    for (const m of line.matchAll(TOKEN)) {
      const before = pyRstrip(line.slice(0, m.index));
      const leader = S.leaders.find((ld) => before.endsWith(ld));
      if (leader === undefined) continue;
      const ahead = before.slice(0, before.length - leader.length);
      if ((ahead && !LEADER_PREFIX.has(ahead[ahead.length - 1])) || inString(ahead)) continue; // URL fragment, lookalike, or in a string
      const tail = TAIL.exec(stripCloser(line.slice(m.index + m[0].length)));
      if (!tail) {
        out.warnings.push(`${path}:${lineno}: ${S.malformed}`);
        break;
      }
      const rules = tail.groups.rules ? new Set(tail.groups.rules.split(",").map((r) => pyStrip(r).toUpperCase())) : new Set([S.all]);
      const target = m.groups.next ? lineno + 1 : lineno;
      if (!out.byLine.has(target)) out.byLine.set(target, []);
      out.byLine.get(target).push({ rules, marker_line: lineno, justification: pyStrip(tail.groups.why || "") });
      break; // one directive per line
    }
  });
  return out;
}

/** suppressions.apply: split findings into [active, suppressed, warnings]; suppressed copies carry `suppression`. */
export function applySuppressions(findings, files) {
  const byPath = new Map(files.map((f) => [f.path, f]));
  const parsed = new Map();
  const warnings = [];
  files.forEach((f) => {
    if (!f.content.includes(S.marker)) return;
    parsed.set(f.path, parseSuppressions(f.content, f.path, f.language));
    warnings.push(...parsed.get(f.path).warnings);
  });
  const active = [];
  const suppressed = [];
  findings.forEach((f) => {
    const directives = parsed.get(f.file_path);
    let hit = null;
    if (directives && f.line_number != null && byPath.has(f.file_path)) {
      const rule = f.rule_id.toUpperCase();
      hit = (directives.byLine.get(f.line_number) || []).find((d) => d.rules.has(S.all) || d.rules.has(rule)) || null;
    }
    if (hit) suppressed.push({ ...f, suppression: { kind: "inSource", justification: hit.justification, marker_line: hit.marker_line } });
    else active.push(f);
  });
  return [active, suppressed, warnings];
}
