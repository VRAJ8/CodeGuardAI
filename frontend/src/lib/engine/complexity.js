// Code-health heuristic, ported from backend/codeguard/scanners/complexity.py. The browser has neither Radon nor
// Python's ast module, so every language (Python included) gets the decision-point and brace-depth heuristic,
// exactly as the backend measures non-Python files and as analyze_file(..., heuristic=True) does.
import { RULES, compileRegex, pyFixed, pyLen, pyRound } from "./lang";
import { countMatches, globalRegex } from "./regex";

const C = RULES.complexity;
const DECISION = globalRegex(C.decision);
const FUNC = globalRegex(C.func);
const EMPTY_CATCH = globalRegex(C.empty_catch);
const COMMENTS = globalRegex(C.comments);
const STRING_LITERAL = globalRegex(C.string_literal);
const TODO = compileRegex(C.todo);

/** radon's cc_rank, A (simple) to F. */
export const rank = (cc) => (C.rank_cutoffs.find(([limit]) => cc <= limit) || [null, "F"])[1];

function braceDepth(content) {
  let depth = 0;
  let best = 0;
  for (const ch of content.replace(STRING_LITERAL, "")) {
    if (ch === "{") {
      depth += 1;
      best = Math.max(best, depth);
    } else if (ch === "}") {
      depth = Math.max(0, depth - 1);
    }
  }
  return best;
}

/** [avg cyclomatic, max cyclomatic, nesting depth, empty catch blocks] */
function genericMetrics(content) {
  const stripped = content.replace(COMMENTS, "");
  const decisions = countMatches(DECISION, stripped);
  const funcs = Math.max(countMatches(FUNC, stripped), 1);
  const avg = 1 + decisions / funcs;
  return [avg, Math.trunc(avg * 2), Math.max(braceDepth(stripped) - 1, 0), countMatches(EMPTY_CATCH, stripped)];
}

/** complexity.analyze_file(content, path, language, heuristic=True) -> BugRisk */
export function analyzeFile(content, filePath, language) {
  const lines = content.split("\n");
  const issues = [];
  let score = 0.0;
  let avgCc = 1.0;
  let maxCc = 1;
  let nesting = 0;
  let empty = 0;
  try {
    [avgCc, maxCc, nesting, empty] = genericMetrics(content);
  } catch (e) {
    if (!(e instanceof RangeError)) throw e; // the regex engine's backtracking stack, where Python has no limit
    issues.push("File could not be parsed");
  }

  const n = lines.length;
  if (n > C.large_file.above) {
    score += C.large_file.points; issues.push(`Large file (${n} lines) — consider splitting by responsibility`);
  } else if (n > C.moderate_file.above) {
    score += C.moderate_file.points; issues.push(`Moderately large file (${n} lines)`);
  }

  if (maxCc > C.very_high_cc.above) {
    score += C.very_high_cc.points; issues.push(`Very high cyclomatic complexity (max ${maxCc}, rank ${rank(maxCc)})`);
  } else if (maxCc > C.high_cc.above) {
    score += C.high_cc.points; issues.push(`High cyclomatic complexity (max ${maxCc}, rank ${rank(maxCc)})`);
  }
  if (avgCc > C.high_avg_cc.above) {
    score += C.high_avg_cc.points; issues.push(`Average complexity per block is ${pyFixed(avgCc, 1)}`);
  }

  if (nesting > C.deep_nesting.above) {
    score += C.deep_nesting.points; issues.push(`Deeply nested logic (depth ${nesting})`);
  } else if (nesting > C.nested.above) {
    score += C.nested.points; issues.push(`Nested logic (depth ${nesting})`);
  }

  const longLines = lines.filter((line) => line.length > C.long_line && pyLen(line) > C.long_line).length;
  if (longLines > C.long_lines.above) {
    score += C.long_lines.points; issues.push(`${longLines} lines exceed ${C.long_line} characters`);
  }

  const todos = lines.filter((line) => TODO.test(line)).length;
  if (todos > C.todos.above) {
    score += C.todos.points; issues.push(`${todos} TODO/FIXME markers`);
  }

  if (empty) {
    score += Math.min(C.empty_handler.points * empty, C.empty_handler.cap); issues.push(`${empty} empty exception handler(s) swallow errors`);
  }

  score = Math.min(score, 100.0);
  return {
    file_path: filePath,
    risk_score: pyRound(score, 1),
    complexity: (C.risk_levels.find(([limit]) => score > limit) || [null, "low"])[1],
    issues,
    language,
    lines: n,
    cyclomatic: pyRound(avgCc, 2),
    max_cyclomatic: Math.trunc(maxCc),
    maintainability: pyRound(Math.max(0.0, 100 - score), 1), // no Maintainability Index without Radon
    hotspots: [],
  };
}
