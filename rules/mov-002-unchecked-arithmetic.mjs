/**
 * MOV-002: Integer arithmetic without overflow protection.
 *
 * Two sub-checks:
 *   (a) Multiplication of u64 values without prior cast to u128/u256.
 *   (b) Left shift (<<), which silently discards the high bits on
 *       overflow instead of aborting like + - *. Right shift (>>) is
 *       deliberately NOT flagged: it discards low bits by design
 *       (unscaling, division-by-power-of-two) and cannot overflow.
 *
 * Why it matters: The Cetus $223M exploit root cause was an incorrect
 * overflow check on a LEFT shift operation. Kriya had the identical bug.
 * Any u64 * u64 that could exceed 2^64 needs u128 promotion BEFORE
 * the multiplication, not after. A left shift is worse — it doesn't
 * abort at all, it silently loses the high bits.
 *
 * Uses the Move parser for type tracking: if either operand is known
 * to be u128 or u256 (from let declaration, cast, or naming convention),
 * the multiplication is safe and not flagged.
 */

import { parseModule, getVarType, WIDE_TYPES } from '../scripts/move-parser.mjs';

const RULE_ID = 'MOV-002';
const SEVERITY = 'HIGH';
const TITLE = 'integer multiplication may overflow without u128 promotion';

/**
 * @param {string} source
 * @param {string} filename
 * @returns {Array<{rule, severity, file, line, message}>}
 */
export function check(source, filename) {
  const findings = [];
  const mod = parseModule(source);
  // Split ONCE, shared by both part (a) below and part (b) further down.
  // Previously this was recomputed on EVERY multiplication match (inside
  // the loop below) as well as a second time before part (b) -- pure
  // waste, since `source` never changes within one check() call and
  // `.split('\n')` is a deterministic function of it. Trivial and
  // provably behaviour-neutral: same input, same output, computed once
  // instead of once-per-match-plus-once-more.
  const lines = source.split('\n');

  for (const fn of mod.functions) {
    // skip test functions
    if (fn.isTest || fn.isTestOnly) continue;
    if (!fn.body) continue;

    for (const mul of fn.body.multiplications) {
      const leftType = mul.leftType || getVarType(fn, mul.left);
      const rightType = mul.rightType || getVarType(fn, mul.right);

      // skip if either operand is u128/u256
      if (leftType && WIDE_TYPES.has(leftType)) continue;
      if (rightType && WIDE_TYPES.has(rightType)) continue;

      // skip if both are literals
      if (/^\d+$/.test(mul.left) && /^\d+$/.test(mul.right)) continue;

      // skip if naming convention indicates wide type
      if (/_u256$/.test(mul.left) || /_u256$/.test(mul.right)) continue;
      if (/_u128$/.test(mul.left) || /_u128$/.test(mul.right)) continue;

      // get the source line for additional context checks (shared `lines`,
      // split once at the top of check() -- see the comment there)
      const lineText = (lines[mul.line - 1] || '').trim();

      // skip if the line has an inline cast (as u128/u256)
      if (/as\s+u128/.test(lineText) || /as\s+u256/.test(lineText)) continue;

      // skip const declarations
      if (/const\s+\w+\s*:\s*u\d+\s*=/.test(lineText)) continue;
      if (/:\s*u128\s*=/.test(lineText) || /:\s*u256\s*=/.test(lineText)) continue;

      // skip lines that are shift operations (handled separately below)
      if (/<<|>>/.test(lineText)) continue;

      findings.push({
        rule: RULE_ID,
        severity: SEVERITY,
        file: filename,
        line: mul.line,
        message: `${TITLE}: \`${mul.left} * ${mul.right}\`${leftType ? ` (${mul.left}: ${leftType})` : ''}${rightType ? ` (${mul.right}: ${rightType})` : ''} — cast to u128 before multiplying to prevent overflow`,
      });
    }
  }

  // (b) Bit-shift detection — `<<` silently discards the HIGH bits on
  // overflow with no abort, the same shift-side hazard as the Cetus
  // checked_shlw bug this rule's docstring cites (an incorrectly-checked
  // LEFT shift). `>>` is deliberately NOT flagged: a right shift discards
  // LOW bits by design (fixed-point unscaling, division-by-power-of-two)
  // and cannot overflow or "wrap" the way `<<`/`*` can -- the previous
  // message ("silently wraps on overflow") was simply false for `>>`, and
  // a rule that asserts something false teaches users to ignore it. This
  // also removes `>>`'s single largest false-positive source as a
  // consequence, not as a separate fix: two closing generic type brackets
  // (`vector<vector<u8>>`) produce a literal `>>` with no shift anywhere
  // nearby, and nested-generic-heavy Move code (VecMap/VecSet/vector of
  // vector) hit this constantly. `<<` has no equivalent ambiguity --
  // Move's generic syntax only ever OPENS with a single `<` (an
  // identifier always separates two nested opens, e.g. `A<B<C>>`), so a
  // literal `<<` is unambiguously a real left-shift operator and needs no
  // "is this actually a shift" guard.
  // (`lines` is the same shared split from the top of check() -- see the
  // comment there; no longer recomputed here.)
  let inTestBlock = false;
  let inTestOnlyModule = false;

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('//')) continue;
    if (/#\[test_only\]/.test(trimmed)) { inTestOnlyModule = true; continue; }
    if (/#\[test[\],\s]/.test(trimmed)) { inTestBlock = true; continue; }
    if (/\bfun\b/.test(trimmed) && !/#\[test/.test(trimmed)) {
      inTestBlock = false;
      if (inTestOnlyModule) { inTestOnlyModule = false; continue; }
    }
    if (inTestBlock || inTestOnlyModule) continue;

    // detect << anywhere on the line, single-line function body included
    // -- a signature-plus-body line (`fun f(a: u64): u64 { a << b }`) is
    // not "just a type annotation" just because a `: uNN` also appears on
    // it earlier in the same line.
    if (trimmed.includes('<<')) {
      // skip if line is a const declaration (compile-time, no runtime risk)
      if (/const\s+\w+/.test(trimmed)) continue;
      // skip if operand is already u128/u256
      if (/as\s+u128/.test(trimmed) || /as\s+u256/.test(trimmed)) continue;
      if (/u128\s*<</.test(trimmed) || /u256\s*<</.test(trimmed)) continue;

      findings.push({
        rule: RULE_ID,
        severity: SEVERITY,
        file: filename,
        line: i + 1,
        message: `bit-shift \`<<\` silently discards the high bits on overflow — unlike +/-/*, a left shift does NOT abort; validate the shift amount and operand width or cast to a wider type first`,
      });
    }
  }

  return findings;
}

export const meta = { id: RULE_ID, severity: SEVERITY, title: TITLE };
