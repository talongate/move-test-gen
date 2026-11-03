/**
 * move-parser.mjs — lightweight Move source parser for lint rules.
 *
 * NOT a full compiler. Extracts function-level structure:
 *   - function signatures (visibility, name, params with types, return type)
 *   - variable declarations with inferred types
 *   - assert locations
 *   - type casts (as u128, as u256, as u64)
 *
 * Rules receive parsed functions instead of raw text, so they can
 * ask "what type is this variable?" without regex guessing.
 */

import { stripBlockComments } from './strip-comments.mjs';

export const WIDE_TYPES = new Set(['u128', 'u256']);

// A line that is ENTIRELY one or more visibility/entry modifier tokens,
// with no `fun` keyword yet -- the leading tokens of a declaration wrapped
// across lines (`public(package)\nentry fun f(...)`). Never matches a line
// that also has other content, so it can't accidentally swallow an
// unrelated statement.
const BARE_VIS_RE = /^(?:public\s*\(\s*(?:package|friend)\s*\)|public|entry)(?:\s+(?:public\s*\(\s*(?:package|friend)\s*\)|public|entry))*$/;

/**
 * Parse a Move source file into module-level structure.
 * @param {string} source — file content
 * @returns {{ moduleName: string, functions: ParsedFunction[], constants: Constant[] }}
 */
export function parseModule(source) {
  // Strip block comments up front: a #[test_only]/#[test] attribute (or a
  // const/module declaration) sitting inside a commented-out block is not
  // attached to anything real, and extractFunctions()'s attribute
  // pass-through would otherwise walk straight through a /* ... */ line
  // (single- or multi-line) as if it were blank. stripBlockComments()
  // preserves line count, so downstream line numbers stay correct.
  const stripped = stripBlockComments(source);
  const lines = stripped.split('\n');
  const moduleName = extractModuleName(stripped);
  const constants = extractConstants(lines);
  const functions = extractFunctions(lines);
  return { moduleName, constants, functions };
}

function extractModuleName(source) {
  const m = source.match(/module\s+([\w:]+)/);
  return m ? m[1] : 'unknown';
}

/**
 * @typedef {{ name: string, type: string, value: string }} Constant
 */
function extractConstants(lines) {
  const constants = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('//')) continue;
    const m = trimmed.match(/const\s+(\w+)\s*:\s*(\w+)\s*=\s*(.+);/);
    if (m) {
      constants.push({ name: m[1], type: m[2], value: m[3].trim() });
    }
  }
  return constants;
}

/**
 * @typedef {{
 *   name: string,
 *   visibility: 'public'|'public(friend)'|'public entry'|'entry'|'private',
 *   isMacro: boolean,
 *   typeParams: string[],
 *   params: { name: string, type: string, isMut: boolean, isRef: boolean }[],
 *   returnType: string|null,
 *   startLine: number,
 *   endLine: number,
 *   isTestOnly: boolean,
 *   isTest: boolean,
 *   body: FunctionBody
 * }} ParsedFunction
 */

/**
 * @typedef {{
 *   variables: { name: string, type: string|null, line: number }[],
 *   asserts: { line: number, code: string|null, condition: string }[],
 *   casts: { line: number, expr: string, fromType: string|null, toType: string }[],
 *   multiplications: { line: number, left: string, right: string, leftType: string|null, rightType: string|null }[],
 *   divisions: { line: number, numerator: string, denominator: string }[],
 *   calls: { line: number, fn: string }[],
 * }} FunctionBody
 */

function extractFunctions(lines) {
  const functions = [];
  let i = 0;

  // An attribute belongs to the item it is directly attached to, never to
  // whatever function happens to follow within N lines. These flags carry
  // an attribute across blank lines, comments, and stacked attribute lines
  // (none of which are items of their own) but are cleared the instant we
  // reach an actual item -- `use`, `struct`, `const`, or a `fun` that
  // consumes them. That is the only way an attribute is "attached": nothing
  // but pass-through lines between it and its item.
  let pendingTestOnly = false;
  let pendingTest = false;
  // A visibility/entry modifier with nothing else on its line (a wrapped
  // `public(package)\nentry fun f(...)` declaration) is not a complete item
  // on its own -- accumulate it and hand it to whichever `fun` line follows,
  // the same "attach forward" shape as the attribute pending flags above.
  let pendingVisPrefix = '';

  while (i < lines.length) {
    const trimmed = lines[i].trim();

    if (trimmed === '' || trimmed.startsWith('//')) { i++; continue; }

    // A line that is ONLY an attribute (no same-line item) -- carry its
    // flag forward and keep scanning for the item it decorates. A trailing
    // `//` comment (`#[test_only] // helper used by the suite`) doesn't
    // disqualify it -- strip that before checking, same idiom parseBody()
    // already uses for the identical reason.
    const attrCodeOnly = trimmed.replace(/\/\/.*$/, '').trim();
    const attrOnly = attrCodeOnly.match(/^#\[([^\]]*)\]$/);
    if (attrOnly) {
      if (/^test_only\b/.test(attrOnly[1])) pendingTestOnly = true;
      else if (/^test\b/.test(attrOnly[1])) pendingTest = true;
      // any other attribute (#[allow(...)], #[expected_failure(...)]) is
      // just another line stacked above the same item -- leave flags as-is.
      i++;
      continue;
    }

    // A bare visibility/entry fragment, no `fun` on the line yet -- hold it
    // rather than treating it as a "different item" boundary.
    if (!/\bfun\b/.test(trimmed) && BARE_VIS_RE.test(trimmed)) {
      pendingVisPrefix = pendingVisPrefix ? `${pendingVisPrefix} ${trimmed}` : trimmed;
      i++;
      continue;
    }

    // detect function start -- tolerates a leading same-line attribute
    // (`#[test_only] fun helper() {`) and a leading visibility fragment
    // held on an earlier line, see parseFunctionSignature.
    const fnInfo = parseFunctionSignature(lines, i, pendingVisPrefix);
    pendingVisPrefix = '';
    if (fnInfo) {
      if (/^#\[test_only\]/.test(trimmed)) fnInfo.isTestOnly = true;
      if (/^#\[test[\],\s]/.test(trimmed)) fnInfo.isTest = true;
      if (pendingTestOnly) fnInfo.isTestOnly = true;
      if (pendingTest) fnInfo.isTest = true;
      pendingTestOnly = false;
      pendingTest = false;

      // find function body boundaries
      const bodyRange = findBraceBlock(lines, fnInfo.sigEndLine);
      if (bodyRange) {
        fnInfo.endLine = bodyRange.end;
        const bodyLines = lines.slice(bodyRange.start, bodyRange.end + 1);
        fnInfo.body = parseBody(bodyLines, bodyRange.start);
        functions.push(fnInfo);
        i = bodyRange.end + 1;
        continue;
      }
    }

    // Reached a different item (use/struct/const, an unmatched fun, or any
    // other code) -- any pending attribute belonged to THIS item, not to
    // whatever function comes later, so it does not carry any further.
    pendingTestOnly = false;
    pendingTest = false;
    i++;
  }

  return functions;
}

function parseFunctionSignature(lines, startIdx, externalPrefix = '') {
  const rawLine = lines[startIdx].trim();
  // A caller may have accumulated leading visibility/entry tokens from
  // earlier lines (`public(package)\nentry fun f(...)`) -- fold them in
  // before matching, so a wrapped declaration is seen as one signature.
  const line = externalPrefix ? `${externalPrefix} ${rawLine}` : rawLine;

  // Strip a leading same-line attribute (`#[test_only] fun foo() {`) so the
  // signature regex still anchors correctly. A stripped attribute CAN carry
  // its own parens (`#[allow(lint(self_transfer))] public fun payout(...)`)
  // -- the param-collector loop below uses this stripped line rather than
  // the raw one for its own starting line, specifically so a balanced
  // paren pair inside the attribute never gets mistaken for the real
  // parameter list and truncates it early.
  // A trailing `//` comment is not code -- searching for `fun` unanchored
  // (below) would otherwise let a comment like "// call fun helper(x) here"
  // masquerade as a real declaration. Strip it before matching; this never
  // affects a genuine signature, since `fun`/its params are always CODE.
  const sigLine = line.replace(/^(?:#\[[^\]]*\]\s*)+/, '').replace(/\/\/.*$/, '');

  // match function declaration. `public(package) entry` / `public(friend)
  // entry` (package-scoped in name only -- `entry` makes it a PTB target
  // regardless) are distinct alternatives, not derived from combining the
  // bare forms: the bare-form alternatives on their own stop consuming at
  // the closing `)`, so `entry` right after would never be reached without
  // its own explicit alternative.
  //
  // `macro` is its OWN optional group, after the visibility alternatives
  // and before `fun`. Move macros are expanded at the call site and have
  // no runtime representation (move-book.com/move-basics/macros/), so an
  // `entry` marker on one is at best meaningless -- but the Move Book
  // does not state that `entry macro` is rejected, so the group is
  // placed to parse it if it appears rather than to assume it cannot:
  // `public(package) entry macro fun f(...)` still matches (the entry
  // alternatives above consume first, `macro` consumes next), and
  // MOV-011 still fires on it unchanged.
  //
  // NOT anchored with `^`: a one-line module (`module d::m { public fun
  // f(...) { ... } }`) packs the module header, and possibly a closing
  // brace from a prior statement, onto the SAME physical line as the
  // function signature -- an anchored match can never reach `fun` there.
  // Un-anchoring is a strict superset for every existing multi-line caller:
  // a signature that already started at column 0 still matches at the same
  // position (nothing precedes it to try first), so no prior behavior
  // changes; it additionally finds a signature that starts mid-line. Both
  // properties (the macro group AND the un-anchoring) are independent --
  // merged from two branches that each added one -- so a one-line module
  // whose function is a macro is matched too.
  const fnRegex = /(public\s+entry\s+|public\(package\)\s+entry\s+|public\(friend\)\s+entry\s+|public\(friend\)\s+|public\(package\)\s+|public\s+|entry\s+)?(macro\s+)?fun\s+(\w+)(?:<([^>]*)>)?\s*\(/;
  const m = sigLine.match(fnRegex);
  if (!m) return null;

  const visRaw = (m[1] || '').trim();
  const visibility = visRaw === '' ? 'private' :
    visRaw.includes('friend') && visRaw.includes('entry') ? 'public(friend) entry' :
    visRaw.includes('package') && visRaw.includes('entry') ? 'public(package) entry' :
    visRaw.includes('friend') ? 'public(friend)' :
    visRaw.includes('entry') && visRaw.includes('public') ? 'public entry' :
    visRaw.includes('entry') ? 'entry' : 'public';

  const isMacro = Boolean(m[2]);
  const name = m[3];
  const typeParams = m[4] ? m[4].split(',').map(t => t.trim()) : [];

  // Where the REAL parameter list's own opening paren sits in sigLine --
  // fnRegex's match already ends with `\s*\(`, consuming exactly up to and
  // including it, so m.index + m[0].length is that position (m.index is 0
  // for every pre-existing multi-line caller, where the signature already
  // started at column 0; it is nonzero only for the one-line-module case
  // the unanchored regex above now also matches). A visibility prefix can
  // carry its own balanced parens before this point (`public(package)`,
  // `public(friend)`) -- starting the scan here, not at char 0, is what
  // keeps them from being mistaken for the parameter list itself.
  const parenStart = m.index + m[0].length - 1;

  // collect full parameter list (may span multiple lines)
  let paramStr = '';
  let sigEndLine = startIdx;
  let depth = 0;
  let started = false;
  for (let j = startIdx; j < Math.min(startIdx + 15, lines.length); j++) {
    // The starting line may carry a same-line attribute prefix, and/or a
    // visibility modifier with its own parens, before the real parameter
    // list (see sigLine/parenStart above) -- slice both away so only the
    // real `(...)` is ever counted. Every later line has no such prefix.
    const lineText = j === startIdx ? sigLine.slice(parenStart) : lines[j];
    for (const ch of lineText) {
      if (ch === '(') { depth++; started = true; }
      if (started && depth > 0) paramStr += ch;
      if (ch === ')') { depth--; if (started && depth === 0) { sigEndLine = j; break; } }
    }
    if (started && depth === 0) break;
  }

  // remove outer parens
  paramStr = paramStr.slice(1);
  const params = parseParams(paramStr);

  // find return type (after `)` and before `{`)
  let returnType = null;
  for (let j = sigEndLine; j < Math.min(sigEndLine + 3, lines.length); j++) {
    const retMatch = lines[j].match(/\)\s*:\s*([^{]+)/);
    if (retMatch) {
      returnType = retMatch[1].trim();
      sigEndLine = j;
      break;
    }
  }

  return {
    name,
    visibility,
    isMacro,
    typeParams,
    params,
    returnType,
    startLine: startIdx + 1,
    sigEndLine,
    endLine: startIdx + 1,
    isTestOnly: false,
    isTest: false,
    body: null,
  };
}

// Exported so a rule can split a parameter list without hand-rolling its
// own comma split. A naive split has no angle-bracket awareness: a
// generic's internal comma (`Table<u64, Bbbb>`) cuts it into two
// fragments, and the second, colon-less fragment can hit an unanchored
// `(\w+)` with nothing to stop it, O(n^2) over a long second-argument
// name. This function tracks `<`/`>` depth correctly, so rules should
// reuse it rather than keep a second implementation of the same job.
export function parseParams(paramStr) {
  if (!paramStr.trim()) return [];
  const params = [];
  // split by comma, but respect angle brackets
  let depth = 0;
  let current = '';
  for (const ch of paramStr) {
    if (ch === '<') depth++;
    // Clamped at 0, never negative: a macro lambda-type param
    // (`$f: |u64| -> u64`) carries a bare `>` in its `->` that never
    // opened a `<` -- an unclamped depth-- drives depth negative, and
    // the NEXT real top-level comma (separating this param from the
    // next) then fails its `depth === 0` check and gets silently
    // swallowed into the current param's text instead of splitting.
    if (ch === '>' && depth > 0) depth--;
    if (ch === ',' && depth === 0) {
      params.push(parseOneParam(current.trim()));
      current = '';
    } else {
      current += ch;
    }
  }
  if (current.trim()) params.push(parseOneParam(current.trim()));
  return params.filter(Boolean);
}

function parseOneParam(s) {
  if (!s) return null;
  // patterns: `name: Type`, `name: &Type`, `name: &mut Type`, `_: Type`,
  // `$name: Type` (a macro's own expression/type parameter -- Move 2024
  // prefixes both with `$`; keeping it here is what lets the body-level
  // extraction below match the SAME source text a macro body actually
  // uses, e.g. `$a * $b`, rather than a name the source never contains).
  //
  // The name is anchored to the start of its word-run: a parameter with
  // no `:` after a long word (`f(aaaa...aaaa, x: u64)`, which the parser
  // is handed as text whether or not the compiler would accept it) made
  // the unanchored `\w+` retry the whole run from every offset, O(n^2).
  // Same anchor, same reasoning, as the operand regexes in parseBody.
  const m = s.match(/(\$\w+|(?<!\w)\w+)\s*:\s*(&mut\s+|&)?(.+)/);
  if (!m) return null;
  // clean trailing parens/commas/whitespace from type
  const rawType = m[3].trim().replace(/[),;\s]+$/, '');
  return {
    name: m[1],
    type: rawType,
    isMut: !!m[2] && m[2].includes('mut'),
    isRef: !!m[2],
  };
}

function findBraceBlock(lines, startSearch) {
  let depth = 0;
  let blockStart = null;
  for (let i = startSearch; i < lines.length; i++) {
    for (const ch of lines[i]) {
      if (ch === '{') {
        if (blockStart === null) blockStart = i;
        depth++;
      }
      if (ch === '}') {
        depth--;
        if (depth === 0 && blockStart !== null) {
          return { start: blockStart, end: i };
        }
      }
    }
  }
  return null;
}

function parseBody(bodyLines, offset) {
  const variables = [];
  const asserts = [];
  const casts = [];
  const multiplications = [];
  const divisions = [];
  const calls = [];

  // track known variable types
  const varTypes = {};

  for (let i = 0; i < bodyLines.length; i++) {
    const line = bodyLines[i];
    const trimmed = line.trim();
    const lineNo = offset + i + 1;

    if (trimmed.startsWith('//')) continue;

    // variable declaration: let name: Type = ...
    const letTyped = trimmed.match(/let\s+(?:mut\s+)?(\w+)\s*:\s*(\w+)/);
    if (letTyped) {
      const [, vname, vtype] = letTyped;
      variables.push({ name: vname, type: vtype, line: lineNo });
      varTypes[vname] = vtype;
    }

    // variable declaration with cast: let name = (expr as u128)
    const letCast = trimmed.match(/let\s+(?:mut\s+)?(\w+)\s*=.*\bas\s+(u(?:8|16|32|64|128|256))\s*\)/);
    if (letCast && !letTyped) {
      const [, vname, castType] = letCast;
      variables.push({ name: vname, type: castType, line: lineNo });
      varTypes[vname] = castType;
    }

    // destructuring with casts: let (a, b) = ((x as u256), (y as u256))
    const letDestruct = trimmed.match(/let\s+\(([^)]+)\)\s*=\s*\((.+)\)/);
    if (letDestruct && !letTyped) {
      const names = letDestruct[1].split(',').map(s => s.trim());
      const exprs = letDestruct[2];
      // find all cast types in order
      const castTypes = [...exprs.matchAll(/as\s+(u(?:128|256))\)/g)].map(c => c[1]);
      for (let k = 0; k < names.length && k < castTypes.length; k++) {
        const vname = names[k];
        if (vname && castTypes[k]) {
          variables.push({ name: vname, type: castTypes[k], line: lineNo });
          varTypes[vname] = castTypes[k];
        }
      }
    }

    // variable assigned from expression involving a known-wide variable
    // let numerator1 = liquidity_u256 << RESOLUTION → u256
    // let diff = a_u128 - b_u128 → u128
    if (!letTyped && !letCast) {
      const letExpr = trimmed.match(/let\s+(?:mut\s+)?(\w+)\s*=\s*(.+)/);
      if (letExpr) {
        const [, vname, expr] = letExpr;
        const tokens = expr.match(/\w+/g) || [];
        for (const tok of tokens) {
          const tokType = varTypes[tok];
          if (tokType && WIDE_TYPES.has(tokType)) {
            variables.push({ name: vname, type: tokType, line: lineNo });
            varTypes[vname] = tokType;
            break;
          }
        }
      }
    }

    // variable from function call with known return type suffix
    // let x_u256 = ...; (naming convention)
    const letSuffix = trimmed.match(/let\s+(?:mut\s+)?(\w+_(u(?:128|256)))\b/);
    if (letSuffix && !letTyped && !letCast) {
      const [, vname, inferredType] = letSuffix;
      variables.push({ name: vname, type: inferredType, line: lineNo });
      varTypes[vname] = inferredType;
    }

    // assert
    const assertMatch = trimmed.match(/assert!\s*\((.+)/);
    if (assertMatch) {
      const condStr = assertMatch[1];
      const codeMatch = condStr.match(/,\s*(\w+)\s*\)$/);
      asserts.push({
        line: lineNo,
        code: codeMatch ? codeMatch[1] : null,
        condition: condStr,
      });
    }

    // A trailing `//` comment is not code -- matching against it can turn a
    // lookalike mention (e.g. `// old code used (x as u64) here`) into a
    // phantom finding alongside the real one. The loop-level comment-only-
    // line skip above only covers a comment that IS the whole line.
    const codeOnly = trimmed.replace(/\/\/.*$/, '').trim();

    // type casts: (expr as uXX) — handle both simple and nested parens
    for (const cm of codeOnly.matchAll(/\(([^)]+?)\s+as\s+(u(?:8|16|32|64|128|256))\)/g)) {
      casts.push({
        line: lineNo,
        expr: cm[1].trim(),
        fromType: inferType(cm[1].trim(), varTypes),
        toType: cm[2],
      });
    }
    // also catch `) as uXX)` pattern (closing a multi-line expression)
    const trailingCast = codeOnly.match(/\)\s+as\s+(u(?:8|16|32|64|128|256))\)\s*;?\s*$/);
    if (trailingCast) {
      casts.push({
        line: lineNo,
        expr: '(multi-line expression)',
        fromType: null,
        toType: trailingCast[1],
      });
    }

    // multiplications. `\$?` tolerates a macro's own `$`-prefixed
    // parameter used directly as an operand (`$a * $b`) -- without it,
    // `\w+` cannot match a `$`-led token at all, so a macro body
    // multiplying two of its own params was invisible here, not merely
    // mis-typed: MOV-002 had nothing in `multiplications` to iterate.
    //
    // The LEFT operand is anchored to the start of its word-run
    // (`(?<!\w)`). Unanchored, `\w+` retried the whole run from every
    // offset inside it, so one long identifier made this line O(n^2)
    // (measured, node --cpu-prof: the dominant cost of a 40,000-character
    // fixture). The anchor makes the regex try each run once -- linear --
    // and, unlike a `\w{1,128}` bound, it never changes WHAT is captured:
    // a bound has to give up somewhere, and the engine then either
    // slides the match start rightward (capturing the run's trailing 128
    // characters as the left operand) or refuses the line outright, and
    // both change a verdict downstream. Here the left operand is always
    // the whole run and the right operand (start pinned right after the
    // operator) is always the whole run, so every consumer compares a
    // name against a name spelled the same way, at any length: a
    // `getVarType` lookup finds the declaration, a `_u128` suffix guard
    // sees the suffix, MOV-003's guard set matches its divisor. No name
    // is truncated, so no two distinct names can be made to collide.
    //
    // `\$\w+` is tried first and is deliberately NOT anchored: a `$` is
    // never a word character, so `x$y * z` starts its operand at the `$`
    // exactly as an unanchored `\$?\w+` would. Each `$` starts at most
    // one scan of the run behind it, so that stays linear too.
    for (const mm of codeOnly.matchAll(/(\$\w+|(?<!\w)\w+)\s*\*\s*(\$?\w+)/g)) {
      multiplications.push({
        line: lineNo,
        left: mm[1],
        right: mm[2],
        leftType: varTypes[mm[1]] || null,
        rightType: varTypes[mm[2]] || null,
      });
    }

    // divisions -- same `\$?` tolerance and the same run-start anchor on
    // the left operand, for the same reasons, kept in sync with the
    // multiplication regex directly above. (Unconsumed by any rule today --
    // fixed anyway so the next rule that reads `divisions` does not
    // inherit a truncated or slid name.)
    for (const dm of codeOnly.matchAll(/(\$\w+|(?<!\w)\w+)\s*\/\s*(\$?\w+)/g)) {
      divisions.push({
        line: lineNo,
        numerator: dm[1],
        denominator: dm[2],
      });
    }

    // function calls -- same bound on both `\w+` runs in the identifier
    // path (`name` and each `::segment`); this was the LARGEST single
    // cost measured, 6166ms of the same 8958ms run. Unlike the two
    // operand regexes above this one keeps the `{1,128}` bound: `calls`
    // is read for DISPLAY only (no rule compares a call name by equality
    // or suffix, and none decides a verdict from it), so a name cut to
    // its trailing 128 characters costs nothing more than a shorter
    // label. If a rule ever starts comparing `calls[].fn`, give this the
    // run-start anchor the operands use instead of relying on the bound.
    const callMatch = trimmed.match(/(\w{1,128}(?:::\w{1,128})*)\s*(?:<[^>]*>)?\s*\(/);
    if (callMatch && !trimmed.match(/^(let|if|while|assert!|fun)\b/)) {
      calls.push({ line: lineNo, fn: callMatch[1] });
    }
  }

  return { variables, asserts, casts, multiplications, divisions, calls };
}

function inferType(expr, varTypes) {
  // direct variable lookup
  if (varTypes[expr]) return varTypes[expr];
  // literal number
  if (/^\d+$/.test(expr)) return 'literal';
  return null;
}

/**
 * Get the type of a variable at a given line within a parsed function.
 */
export function getVarType(fn, varName) {
  if (!fn.body) return null;
  for (const v of fn.body.variables) {
    if (v.name === varName) return v.type;
  }
  // check params
  for (const p of fn.params) {
    if (p.name === varName) return p.type;
  }
  return null;
}

/**
 * Check if a function has an assert guarding a specific condition
 * before a given line.
 */
export function hasAssertBefore(fn, lineNo, pattern) {
  if (!fn.body) return false;
  for (const a of fn.body.asserts) {
    if (a.line < lineNo && pattern.test(a.condition)) return true;
  }
  return false;
}
