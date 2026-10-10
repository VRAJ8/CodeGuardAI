// Python `re` call semantics over the specs in rules.generated.json (compiled by lang.compileRegex). A regex with the
// g flag carries lastIndex between calls, so re.search / re.match go through the cached non-global regex, and the g
// regexes here are only used by calls that reset lastIndex themselves (String.prototype.match, replace, matchAll).
import { compileRegex } from "./lang";

const SYNTAX = /[\\^$.*+?()[\]{}|/]/g;

/** For re.findall / re.finditer / re.sub: a g-flag copy, never shared with search. */
export const globalRegex = (spec) => compileRegex(spec, "g");

/** len(re.findall(pattern, s)) for a g-flag regex. */
export const countMatches = (re, s) => (s.match(re) || []).length;

/** re.escape for a literal spliced into a "u" pattern. Python escapes a few more characters ("-", "#", space...),
 *  but outside a class those are literals in both dialects, and "u" mode rejects their escapes. */
export const escapeRegex = (text) => text.replace(SYNTAX, "\\$&");

/** prefix + re.escape(literal) + suffix, compiled the way the specs are (dependencies.DEP_LINE). */
export const literalRegex = (prefix, literal, suffix) =>
  new RegExp(prefix.pattern + escapeRegex(literal) + suffix.pattern, prefix.flags);
