/**
 * MOV-005: Authorization check result discarded (Typus pattern).
 *
 * Flags calls to bool-returning authorization functions where the
 * result is not bound to a variable, not passed to assert!, and
 * not used in an if/while condition. The call runs but the answer
 * is thrown away — the authorization is theater.
 *
 * Why it matters: Typus Finance lost $3.44M because update_v2 called
 * vector::contains() on an authority whitelist and discarded the bool.
 * The check looked correct to every reviewer — the function name,
 * the arguments, even the comment ("check authority") all matched.
 * Only the assert! was missing. Move has no #[must_use] to catch this.
 *
 * Detection: standalone expression statements matching known auth
 * patterns without let binding, assert!, or if/while context.
 */

const RULE_ID = 'MOV-005';
const SEVERITY = 'HIGH';
const TITLE = 'authorization check result discarded';

// Only bool-returning functions. Void functions that abort internally
// (like Typus's admin::verify() which asserts inside) are NOT flagged —
// calling them without binding the result is correct because there is no result.
const AUTH_PATTERNS = [
  /vector::contains\s*\(/,
  // `<word>::contains(` needs only ONE word character before the `::` --
  // that is all the old `\w+::contains` could ever be asked. Written with
  // `\w+` it was O(n^2) on a long identifier (unanchored, retried from
  // every offset inside the run; ~100% of a 6667ms run on a 40,000-char
  // identifier, evaluated twice per line). A single `\w` is the same
  // boolean at any length and has no quantifier to retry. (A `{1,128}`
  // bound also kept the truthiness here, because sliding preserves it;
  // this is simply the form with nothing to bound.)
  /\w::contains\s*\(/,
  /\bcontains\s*\(/,
  // same one-character form, same reason, directly above.
  /\w::has\s*\(/,
  /\bhas\s*\(/,
  /\bis_authorized\s*\(/,
  /\bis_admin\s*\(/,
  /\bis_owner\s*\(/,
  /\bis_valid\s*\(/,
  /\bhas_role\s*\(/,
  /\bhas_permission\s*\(/,
];

const SAFE_CONTEXTS = [
  /assert!\s*\(/,
  // (?:mut\s+)? -- Move 2024's `let mut x = ...` puts the `mut` keyword
  // between `let` and the bound name; without tolerating it, the pattern
  // required `=` right after `let`'s first identifier and never matched
  // `let mut x = ...` at all, flagging a properly-bound result as discarded.
  /\blet\s+(?:mut\s+)?[a-zA-Z]\w*\s*=/,
  /\bif\s*[\s(]/,
  /\bwhile\s*\(/,
  /\breturn\b/,
  /=\s*$/,
];

/**
 * @param {string} source
 * @param {string} filename
 * @returns {Array<{rule, severity, file, line, message}>}
 */
export function check(source, filename) {
  const findings = [];
  const lines = source.split('\n');

  let skipNextItem = false;
  let inTestModule = false;
  let inTestFun = false;
  let testBraceDepth = 0;
  let moduleBraceDepth = 0;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed === '' || /^\/\//.test(trimmed)) continue;

    if (/^#\[test_only\]/.test(trimmed)) { skipNextItem = true; continue; }
    if (/^#\[test\b/.test(trimmed)) { skipNextItem = true; continue; }

    // track test_only modules
    if (skipNextItem && /\bmodule\b/.test(trimmed)) {
      inTestModule = true;
      skipNextItem = false;
      continue;
    }

    // track test/test_only functions
    if (skipNextItem && /\bfun\b/.test(trimmed)) {
      inTestFun = true;
      testBraceDepth = 0;
      skipNextItem = false;
    }

    if (skipNextItem && !(/\bfun\b/.test(trimmed)) && !(/\bmodule\b/.test(trimmed))) {
      skipNextItem = false;
    }

    // brace tracking for test functions
    if (inTestFun) {
      for (const ch of trimmed) {
        if (ch === '{') testBraceDepth++;
        if (ch === '}') testBraceDepth--;
      }
      if (testBraceDepth <= 0 && trimmed.includes('}')) {
        inTestFun = false;
      }
      continue;
    }

    if (inTestModule) continue;

    // skip _test suffix functions
    if (/\bfun\s+\w+_test\b/.test(trimmed)) {
      inTestFun = true;
      testBraceDepth = 0;
      for (const ch of trimmed) {
        if (ch === '{') testBraceDepth++;
        if (ch === '}') testBraceDepth--;
      }
      continue;
    }

    // strip trailing // comment before matching
    const stripped = trimmed.replace(/\/\/.*$/, '').trim();

    // join multiline statements: if this line has auth pattern but no ;
    // look ahead to accumulate the full statement
    let fullStmt = stripped;
    if (AUTH_PATTERNS.some(p => p.test(stripped)) && !stripped.endsWith(';') && !stripped.endsWith(');')) {
      for (let j = i + 1; j < lines.length && j < i + 5; j++) {
        const cont = lines[j].trim().replace(/\/\/.*$/, '').trim();
        fullStmt += ' ' + cont;
        if (cont.endsWith(';') || cont.endsWith(');')) break;
      }
    }

    const isAuthCall = AUTH_PATTERNS.some(p => p.test(fullStmt));
    if (!isAuthCall) continue;

    const isSafe = SAFE_CONTEXTS.some(p => p.test(fullStmt));
    if (isSafe) continue;

    // check previous line for multi-line assert!/if
    const prevLine = (i > 0 ? lines[i - 1].trim() : '');
    if (/assert!\s*\(\s*$/.test(prevLine)) continue;
    if (/if\s*\(\s*$/.test(prevLine)) continue;

    if (fullStmt.endsWith(';') || fullStmt.endsWith(');')) {
      // The discarded call's NAME, for the message only. Unanchored `\w+`
      // was O(n^2) here too: legal receiver syntax puts a long identifier
      // BEFORE the call (`<40,000-char ident>.has(x);`), so the leading
      // `\w+` ran O(n) from every start offset (measured 123 / 473 / 1777
      // ms at 10k / 20k / 40k chars, x4 per doubling). Anchoring the start
      // to a word-run boundary (`(?<!\w)`) tries each run once, and it
      // captures the same whole name the unbounded form did -- so the
      // message names a >128-character module in full instead of a
      // trailing slice of it. The finding itself never depends on this
      // lookup.
      const callMatch = trimmed.match(/((?<!\w)\w+(?:::\w+)?)\s*\(/);
      const fnName = callMatch ? callMatch[1] : 'call';

      findings.push({
        rule: RULE_ID,
        severity: SEVERITY,
        file: filename,
        line: i + 1,
        message: `${TITLE}: \`${fnName}()\` returns bool but result is discarded — wrap in assert!() to enforce the check`,
      });
    }
  }

  return findings;
}

export const meta = { id: RULE_ID, severity: SEVERITY, title: TITLE };
