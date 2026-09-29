#!/usr/bin/env node
/**
 * Several lint rules (and the shared parser they use) were O(n^2) in
 * physical line length: a PR-gate tool that scans attacker-supplied Move
 * source and takes seconds to minutes on a single long line is a denial-
 * of-service anyone can submit. This case pins the fix: the same findings
 * as before at every name length, and linear time.
 *
 * Cause, found with `node --cpu-prof`: unanchored `\w+`-shaped regexes,
 * each backtracking O(remaining line length) from every non-matching
 * starting position inside one long uninterrupted `\w`-run (digits and
 * identifier characters are both `\w`). That is genuine O(n^2) -- it
 * quadruples per doubling of the line -- not exponential backtracking.
 * Re-running `source.split('\n')` per multiplication is NOT part of the
 * cost: on a fixture with no `*` the multiplication list is empty and
 * that loop never runs. The sites:
 *   - scripts/move-parser.mjs: the multiplication, division and
 *     parameter-name regexes, and the function-call regex (see below)
 *   - rules/mov-003-division-without-zero-check.mjs: its own copy of
 *     the division regex (it does not import the parser's)
 *   - rules/mov-005-unused-auth-result.mjs: the `<word>::contains` and
 *     `<word>::has` patterns and the discarded-call name lookup. These
 *     run on every non-comment line, so a long identifier reaches them
 *     without any auth call being present
 *   - rules/mov-001-missing-access-control.mjs: the `Cap`/`Key` test
 *     over the parameter list
 * MOV-004, MOV-008, MOV-011 and MOV-012 read the same parser, so they
 * inherit the parser's cost and its fix.
 *
 * MOV-005 is exercised with a long IDENTIFIER rather than a long digit
 * literal: a numeric literal that size is expected to be rejected by the
 * Move compiler (its limit is understood to be 78 decimal digits; not
 * re-verified against a toolchain), while a long identifier is expected
 * to compile.
 *
 * The fix anchors each unanchored `\w+` to the start of its word-run
 * (a `(?<!\w)` lookbehind), or drops the quantifier where the pattern
 * only ever needed one word character; MOV-001 uses a literal pre-test
 * plus a per-word check instead of a backtracking pattern. Every run is
 * then tried once, so the cost is linear in the line and each regex
 * captures the same whole name it always did, at any length.
 *
 * No `\w{1,128}` bound is used on any name that is compared. A bound caps
 * the backtracking too, but past 128 characters a bounded capture either
 * slides to the run's trailing slice or refuses the line, and either way
 * a verdict changes; cutting BOTH sides of a comparison to a shared prefix
 * instead makes two names that differ only after the bound collide, which
 * silently drops a real finding. The one remaining bound is the parser's
 * function-call regex, whose captured name is displayed and never compared.
 * The both-direction pins below hold the verdicts at every length.
 *
 * Also fixed, MOV-002's own file: `source.split('\n')` was recomputed on
 * EVERY multiplication match, plus a second time before shift detection
 * -- hoisted to once per check() call. Behaviour-neutral: same `source`
 * string throughout one call, `.split('\n')` is deterministic.
 */
import { readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { check as check001 } from '../../../../rules/mov-001-missing-access-control.mjs';
import { check as check002 } from '../../../../rules/mov-002-unchecked-arithmetic.mjs';
import { check as check003 } from '../../../../rules/mov-003-division-without-zero-check.mjs';
import { check as check005 } from '../../../../rules/mov-005-unused-auth-result.mjs';

const errs = [];
function assert(label, cond) {
  if (!cond) errs.push(label);
}

function makeLongLiteralSrc(digits) {
  const lit = '9'.repeat(digits);
  return `module d::m {
    public fun f(amount: u64) {
        assert!(amount == ${lit}, 1);
    }
}`;
}

// ── Behaviour pin: identical findings on a long-line fixture ──────────
// (a legitimate finding must still fire -- not just "stays clean")

const longLineWithRealMul = `module d::m {
    public fun f(amount: u64, total: u64) {
        let padding = ${'9'.repeat(20000)};
        let m = amount * total;
        m
    }
}`;
assert(
  'MOV-002 still fires on a genuine unpromoted multiply, unaffected by a huge unrelated literal on an earlier line',
  check002(longLineWithRealMul, 'm.move').length === 1
);

const longLineWithRealDiv = `module d::m {
    public fun f(amount: u64, total: u64) {
        let padding = ${'9'.repeat(20000)};
        let q = amount / total;
        q
    }
}`;
assert(
  'MOV-003 still fires on a genuine unchecked division, unaffected by a huge unrelated literal on an earlier line',
  check003(longLineWithRealDiv, 'm.move').length === 1
);

const cleanLongLiteral = makeLongLiteralSrc(20000);
assert('MOV-002 stays silent on a huge literal with no multiplication (unaffected)', check002(cleanLongLiteral, 'm.move').length === 0);
assert('MOV-003 stays silent on a huge literal with no division (unaffected)', check003(cleanLongLiteral, 'm.move').length === 0);

// ── Both directions, at every length that matters ─────────────────────────
// A length-dependent defect is wrong in one of two directions, and a fix
// can trade one for the other without anyone noticing: a name the tool
// should accept gets reported (noise a reviewer dismisses), or a name it
// should report gets dropped (a vulnerability under a green check). A
// check that only asserts the direction the fix was written for cannot see
// the second kind. So every operand position below is pinned both ways --
// the safe spelling must read 0 findings AND the otherwise identical
// unsafe spelling must read exactly 1 -- at 120 (under a 128-character
// mark), 128, 129 (the first length past it), 140 and 200. No verdict
// depends on a length mark; 128 is simply where a `\w{1,128}` bound would
// give up (slide to a trailing slice, or refuse the line), so it is where
// these pins would go red if such a bound were introduced on a compared name.
//
// The example and scenario sources cannot stand in for this: their longest
// word-run is 72 characters, so they are silent about every length past
// 128 by construction.

const NAME_LENGTHS = [120, 128, 129, 140, 200];
function longAlpha(n) { return 'd'.repeat(n); }
function bothWays(label, check, mkSafe, mkUnsafe) {
  for (const n of NAME_LENGTHS) {
    const safe = check(mkSafe(n), 'm.move').length;
    const unsafe = check(mkUnsafe(n), 'm.move').length;
    assert(`${label} @${n}: the safe spelling reads 0 findings (got ${safe})`, safe === 0);
    assert(`${label} @${n}: the unsafe spelling reads exactly 1 finding (got ${unsafe})`, unsafe === 1);
  }
}
// Two distinct names of length n that differ only in their LAST character:
// the shape that would collide if a name were ever cut to a shared prefix.
function namePair(n) { return [longAlpha(n - 1) + 'x', longAlpha(n - 1) + 'y']; }

// MOV-003 -- the denominator against each of the three guard forms. The
// unsafe spelling is either no guard at all or a guard on a DIFFERENT name
// of the same length.
const div003 = (name, guardLine) => `module d::m {
    public fun f(a: u64, ${name}: u64): u64 {
${guardLine}        let q = a / ${name};
        q
    }
}`;
const GUARDS_003 = {
  'assert != 0': (nm) => `        assert!(${nm} != 0, 1);\n`,
  'assert > 0': (nm) => `        assert!(${nm} > 0, 1);\n`,
  'if != 0': (nm) => `        if (${nm} != 0) { let _t = 1; };\n`,
  'if == 0 abort': (nm) => `        if (${nm} == 0) abort 1;\n`,
};
for (const [guardName, guard] of Object.entries(GUARDS_003)) {
  bothWays(
    `MOV-003 division by a long name, guard "${guardName}"`,
    check003,
    (n) => div003(longAlpha(n), guard(longAlpha(n))),
    (n) => div003(longAlpha(n), ''),
  );
  bothWays(
    `MOV-003 division by a long name, guard "${guardName}" on a different name that shares all but the last character`,
    check003,
    (n) => div003(namePair(n)[0], guard(namePair(n)[0])),
    (n) => div003(namePair(n)[0], guard(namePair(n)[1])),
  );
}

// MOV-002 -- a multiply is safe when either operand is known wide, by a
// declared type or by a `_u128`/`_u256` name suffix; unsafe otherwise. Each
// operand position is pinned separately, because they read the operand
// differently: the right one starts right after the `*`, the left one has
// nothing but whitespace or an `=` in front of it.
const mul002 = (params, body) => `module d::m {
    public fun f(${params}): u64 {
${body}        0
    }
}`;
const MUL_SHAPES = {
  'right operand, wide parameter': {
    safe: (n) => mul002(`y: u64, ${longAlpha(n)}: u128`, `        let z = y * ${longAlpha(n)};\n`),
    unsafe: (n) => mul002(`y: u64, ${longAlpha(n)}: u64`, `        let z = y * ${longAlpha(n)};\n`),
  },
  'left operand, wide parameter': {
    safe: (n) => mul002(`${longAlpha(n)}: u128, y: u64`, `        let z = ${longAlpha(n)} * y;\n`),
    unsafe: (n) => mul002(`${longAlpha(n)}: u64, y: u64`, `        let z = ${longAlpha(n)} * y;\n`),
  },
  'left operand, bare statement, wide parameter': {
    safe: (n) => mul002(`${longAlpha(n)}: u128, y: u64`, `        ${longAlpha(n)} * y;\n`),
    unsafe: (n) => mul002(`${longAlpha(n)}: u64, y: u64`, `        ${longAlpha(n)} * y;\n`),
  },
  'right operand, wide `let`': {
    safe: (n) => mul002('y: u64', `        let ${longAlpha(n)}: u128 = 5;\n        let z = y * ${longAlpha(n)};\n`),
    unsafe: (n) => mul002('y: u64', `        let ${longAlpha(n)}: u64 = 5;\n        let z = y * ${longAlpha(n)};\n`),
  },
  'left operand, wide `let`': {
    safe: (n) => mul002('y: u64', `        let ${longAlpha(n)}: u128 = 5;\n        let z = ${longAlpha(n)} * y;\n`),
    unsafe: (n) => mul002('y: u64', `        let ${longAlpha(n)}: u64 = 5;\n        let z = ${longAlpha(n)} * y;\n`),
  },
  'right operand, `_u128` suffix': {
    safe: (n) => mul002(`y: u64, ${longAlpha(n - 5)}_u128: u64`, `        let z = y * ${longAlpha(n - 5)}_u128;\n`),
    unsafe: (n) => mul002(`y: u64, ${longAlpha(n)}: u64`, `        let z = y * ${longAlpha(n)};\n`),
  },
  'left operand, `_u128` suffix': {
    safe: (n) => mul002(`${longAlpha(n - 5)}_u128: u64, y: u64`, `        let z = ${longAlpha(n - 5)}_u128 * y;\n`),
    unsafe: (n) => mul002(`${longAlpha(n)}: u64, y: u64`, `        let z = ${longAlpha(n)} * y;\n`),
  },
  'left operand, `_u256` suffix, bare statement': {
    safe: (n) => mul002(`${longAlpha(n - 5)}_u256: u64, y: u64`, `        ${longAlpha(n - 5)}_u256 * y;\n`),
    unsafe: (n) => mul002(`${longAlpha(n)}: u64, y: u64`, `        ${longAlpha(n)} * y;\n`),
  },
};
for (const [shape, { safe, unsafe }] of Object.entries(MUL_SHAPES)) {
  bothWays(`MOV-002 multiply, ${shape}`, check002, safe, unsafe);
}

// MOV-001 -- a `&mut` parameter is gated when some word in the parameter
// list ends in `Cap`/`Key` after an uppercase letter. The safe spelling
// carries the capability; the unsafe one is the same length with the last
// letters changed so it does not. This is a boolean, so the failure is a
// flip (a gated function reported), not a truncated capture.
const mut001 = (paramTail) => `module d::m {
    public fun f(o: &mut Pool, ${paramTail}) {
    }
}
`;
bothWays(
  'MOV-001 capability parameter, `Cap` after a long lowercase run',
  check001,
  (n) => mut001(`c: &A${'a'.repeat(n)}Cap`),
  (n) => mut001(`c: &A${'a'.repeat(n)}Cop`),
);
bothWays(
  'MOV-001 capability parameter, `Key` after a long lowercase run',
  check001,
  (n) => mut001(`c: &A${'a'.repeat(n)}Key`),
  (n) => mut001(`c: &A${'a'.repeat(n)}Kex`),
);
bothWays(
  'MOV-001 capability parameter, snake_case name ending in `Cap`',
  check001,
  (n) => mut001(`c: &T${'_admin'.repeat(Math.ceil(n / 6))}Cap`),
  (n) => mut001(`c: &T${'_admin'.repeat(Math.ceil(n / 6))}Cop`),
);
// A `Cap` that is only a suffix of a lowercase word is not a capability,
// however long the word; the uppercase before it is what makes it one.
{
  const lowerOnly = check001(mut001(`c: &${'a'.repeat(200)}Cap`), 'm.move').length;
  assert(`MOV-001: a 200-character word ending in Cap with no uppercase before it is not a capability (got ${lowerOnly} findings, want 1)`, lowerOnly === 1);
  const bare = check001(mut001('c: &Cap'), 'm.move').length;
  assert(`MOV-001: the bare word Cap is a capability (got ${bare} findings, want 0)`, bare === 0);
}

// MOV-005 -- a discarded `<name>::contains(...)` / `<name>.has(...)` is a
// finding; the same call wrapped in `assert!` is not. The reported name is
// the whole name, at any length.
const auth005 = (stmt) => `module d::m {
    public fun f(list: &vector<address>, sender: address) {
        ${stmt}
    }
}`;
bothWays(
  'MOV-005 qualified auth call',
  check005,
  (n) => auth005(`assert!(${longAlpha(n)}::contains(list, sender), 1);`),
  (n) => auth005(`${longAlpha(n)}::contains(list, sender);`),
);
bothWays(
  'MOV-005 receiver auth call',
  check005,
  (n) => auth005(`assert!(${longAlpha(n)}.has(sender), 1);`),
  (n) => auth005(`${longAlpha(n)}.has(sender);`),
);
for (const n of NAME_LENGTHS) {
  const f = check005(auth005(`${longAlpha(n)}::contains(list, sender);`), 'm.move');
  assert(
    `MOV-005 @${n}: the message names the ${n}-character module in full, not a slice of it`,
    f.length === 1 && f[0].message.includes(`${longAlpha(n)}::contains`)
  );
}

// ── Loose timing tripwire, explicitly NOT a strict perf SLA.
// 40k digits: roughly 85ms with the fix and roughly 8s without it, on one
// ordinary machine. A 3000ms ceiling is about 35x the fixed time and well
// under the unfixed time -- generous enough that ordinary CI load should
// not trip it, while a regression back to O(n^2) blows past it by orders
// of magnitude at this size. It is a best-effort tripwire only: on a
// severely constrained or contended runner it could still be too tight.
// If it ever flakes, loosen the ceiling rather than delete the guard. ──

{
  const src = makeLongLiteralSrc(40000);
  const t0 = Date.now();
  check002(src, 'm.move');
  const ms = Date.now() - t0;
  assert(`MOV-002 completes a 40k-digit fixture within a generous 3000ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA`, ms < 3000);
}

// ── MOV-005: same defect class, different reachability.
// A 40,000-DIGIT literal is expected to be illegal Move (see the header),
// so the MOV-005 fixture below uses a 40,000-character IDENTIFIER
// instead. AUTH_PATTERNS runs on EVERY non-comment line unconditionally
// (not gated behind an auth-call match first), so a long identifier
// reaches it even on a line that never mentions contains()/has(). ──────

function makeLongIdentSrc(chars) {
  const ident = 'a'.repeat(chars);
  return `module d::m {
    public fun f() {
        let ${ident} = 1;
    }
}`;
}

// Behaviour pin: a genuine auth-discard finding still fires, unaffected
// by a huge unrelated identifier on an earlier line in the same function.
const longIdentWithRealAuthCall = `module d::m {
    public fun f(list: &vector<address>, sender: address) {
        let ${'a'.repeat(20000)} = 1;
        whitelist::contains(list, sender);
    }
}`;
assert(
  'MOV-005 still fires on a genuine discarded whitelist::contains() call, unaffected by a huge unrelated identifier on an earlier line',
  check005(longIdentWithRealAuthCall, 'm.move').length === 1
);

// Behaviour pin: the same call, now bound with assert!(), stays silent --
// confirms SAFE_CONTEXTS detection is unaffected by the bound's length.
const longIdentWithSafeAuthCall = `module d::m {
    public fun f(list: &vector<address>, sender: address) {
        let ${'a'.repeat(20000)} = 1;
        assert!(whitelist::contains(list, sender), 1);
    }
}`;
assert(
  'MOV-005 stays silent when the same call is wrapped in assert!(), unaffected by a huge unrelated identifier on an earlier line',
  check005(longIdentWithSafeAuthCall, 'm.move').length === 0
);

const cleanLongIdent = makeLongIdentSrc(20000);
assert('MOV-005 stays silent on a huge identifier with no auth call anywhere (unaffected)', check005(cleanLongIdent, 'm.move').length === 0);

// MOV-005's discarded-call name lookup, exercised by the
// `<mod>::contains(...)` shape (a receiver call like `x.contains(x)` does
// not reach the long part: the captured segment there is the short method
// name after the dot). The lookup only feeds the message, so what is worth
// pinning is that the whole module name appears in it -- at 128 characters
// and past it -- and that the finding is still reported exactly once.
function longQualifiedAuthCall(n) {
  return `module d::m {
    public fun f(list: &vector<address>, sender: address) {
        ${longAlpha(n)}::contains(list, sender);
    }
}`;
}
{
  const atBound = check005(longQualifiedAuthCall(128), 'm.move');
  assert(
    'MOV-005: a 128-char module name reports 1 finding whose message names the module IN FULL, untruncated',
    atBound.length === 1 && atBound[0].message.includes(`${longAlpha(128)}::contains`)
  );
  const overBound = check005(longQualifiedAuthCall(140), 'm.move');
  assert(
    'MOV-005: a 140-char module name still reports exactly 1 discarded-call finding -- the name lookup must not silently drop the finding it is reporting',
    overBound.length === 1
  );
}

// ── Loose timing tripwire for MOV-005, same discipline as MOV-002's
// above. 40k-char identifier, direct check() call: roughly 13ms with the
// fix and roughly 6s without it, on one ordinary machine. The 2000ms
// ceiling is well under the unfixed time and comfortably above the fixed
// one; if it ever flakes on a loaded CI box, loosen the ceiling rather
// than delete the guard. ────────────────────────────────────────────────

{
  const src = makeLongIdentSrc(40000);
  const t0 = Date.now();
  check005(src, 'm.move');
  const ms = Date.now() - t0;
  assert(`MOV-005 completes a 40k-char identifier fixture within a generous 2000ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA`, ms < 2000);
}

// ── The whole pipeline, not one rule at a time. ─────────────────────────
// MOV-004/008/011 (plus MOV-002/003 again) route through the shared
// parser, so a 40,000-char identifier costs the full lint pipeline every
// rule's share at once -- tens of seconds before the fix. Two more pins:
//
// (1) MOV-005's discarded-call NAME lookup, `(\w+(?:::\w+)?)\s*\(`, runs
// on any line the rule is about to report. Receiver syntax makes it
// reachable with legal Move -- `<long ident>.has(x);` puts the long run
// BEFORE the call, so an unanchored leading `\w+` ran O(n) per start
// position (123 / 473 / 1777 ms at 10k / 20k / 40k chars: x4 per
// doubling).

const receiverShortAuth = `module d::m {
    public fun f(list: &vector<address>, sender: address) {
        list.has(sender);
    }
}`;
{
  const findings = check005(receiverShortAuth, 'm.move');
  assert(
    'MOV-005 still fires on a discarded receiver-syntax list.has(sender); and still names the call `has()` (a real, short receiver is named as before)',
    findings.length === 1 && findings[0].message.includes('`has()`')
  );
}

function makeLongReceiverSrc(chars, method) {
  return `module d::m {
    public fun f(x: u64) {
        ${'a'.repeat(chars)}.${method}(x);
    }
}`;
}
{
  const src = makeLongReceiverSrc(80000, 'has');
  const t0 = Date.now();
  const findings = check005(src, 'm.move');
  const ms = Date.now() - t0;
  assert(`MOV-005 completes an 80k-char receiver-identifier fixture within a generous 1500ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA`, ms < 1500);
  assert('MOV-005 still reports the discarded call on that same 80k-char receiver fixture (a long receiver must not hide the finding)', findings.length === 1);
}

// (2) The sweep. Enumerate NOTHING: every rule file that exists is
// imported and run, so a rule added later -- with an unanchored `\w+` of
// its own -- fails HERE instead of going unnoticed. (A hand-kept roster
// of rule ids goes stale the first time a rule is added.) Scope, stated
// because a clean result is only as wide as its inputs: THIRTEEN shapes of
// ONE class, an unanchored `\w+`/`\w*` meeting a long \w-run -- long
// identifier as a `let` name, a call, a multiplication operand, a cast
// operand, a function name, a receiver, a `&mut` PARAMETER TYPE, a
// generic's SECOND ARGUMENT, a division numerator and denominator, a
// zero-check guard, a `Cap` parameter behind a long alternating-case one,
// and a parameter with no type. It does NOT cover other quadratic shapes
// (an unclosed-`(` run is a separate class), and it does not cover every
// position a parameter list could vary on -- only those constructed here.
const RULES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..', 'rules');
const ruleFiles = readdirSync(RULES_DIR).filter(f => f.endsWith('.mjs')).sort();
assert(`the sweep found the rule files (got ${ruleFiles.length})`, ruleFiles.length >= 9);

const wrap = (body) => `module d::m {\n    public fun f(x: u128, y: u64) {\n        ${body}\n    }\n}\n`;
// Control for the alternating-case shapes: a UNIFORM run only lengthens
// one backtrack attempt per starting position; ALTERNATING case multiplies
// the number of starting positions `[A-Z]\w*`-shaped patterns even try. A
// plain `'a'.repeat(n)` reads 0ms on exactly the sites these shapes exist
// to catch -- the other shapes stay lowercase because their sites don't
// care, but these must not.
function altCase(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += i % 2 === 0 ? 'A' : 'a';
  return s;
}
const SWEEP = [
  { shape: 'let-name', chars: 40000, src: (id) => wrap(`let ${id} = 1;`) },
  { shape: 'call', chars: 40000, src: (id) => wrap(`${id}(x);`) },
  { shape: 'mul-operand', chars: 40000, src: (id) => wrap(`let z = ${id} * y;`) },
  { shape: 'cast-operand', chars: 40000, src: (id) => wrap(`let z = (${id} as u64);`) },
  { shape: 'fun-name', chars: 40000, src: (id) => `module d::m {\n    public fun ${id}(x: u64) {\n    }\n}\n` },
  { shape: 'receiver', chars: 60000, src: (id) => wrap(`${id}.has(x);`) },
  // The six shapes above put the long \w-run in a body statement. These
  // put it in a PARAMETER LIST, which MOV-001's `Cap` test and the shared
  // parameter parser (and so MOV-012) read separately: a body-only sweep
  // reads 0ms on those rules while they are genuinely quadratic.
  {
    shape: 'param-type-altcase', chars: 40000, id: altCase,
    src: (id) => `module d::m {\n    public fun f(o: &mut ${id}, x: u64) {\n        let y = x;\n    }\n}\n`,
  },
  {
    shape: 'generic-2nd-arg', chars: 40000,
    src: (id) => `module d::m {\n    public fun f(o: &mut Table<u64, ${id}>, x: u64) {\n        let y = x;\n    }\n}\n`,
  },
  { shape: 'div-numerator', chars: 40000, src: (id) => wrap(`let q = ${id} / y;`) },
  { shape: 'div-denominator', chars: 40000, src: (id) => wrap(`let q = y / ${id};`) },
  { shape: 'assert-guard', chars: 40000, src: (id) => wrap(`assert!(${id} != 0, 1);`) },
  // A `Cap` that DOES exist further along: the literal pre-test hits, so
  // the precise test runs, and it must still be linear behind a long
  // alternating-case parameter.
  {
    shape: 'cap-behind-altcase', chars: 40000, id: altCase,
    src: (id) => `module d::m {\n    public fun f(o: &mut ${id}, c: &AdminCap) {\n        let y = 1;\n    }\n}\n`,
  },
  // No `:` after the long word, so nothing anchors the parameter name.
  {
    shape: 'param-without-type', chars: 40000,
    src: (id) => `module d::m {\n    public fun f(${id}, x: u64) {\n        let y = x;\n    }\n}\n`,
  },
];
for (const f of ruleFiles) {
  const mod = await import(pathToFileURL(join(RULES_DIR, f)).href);
  for (const { shape, chars, id: idFn, src } of SWEEP) {
    const text = src((idFn || ((n) => 'a'.repeat(n)))(chars));
    const t0 = Date.now();
    mod.check(text, 'm.move');
    const ms = Date.now() - t0;
    assert(`${f} completes the ${chars}-char ${shape} fixture within a generous 1000ms ceiling (got ${ms}ms) -- loose regression tripwire, not a perf SLA`, ms < 1000);
  }
}

if (errs.length) {
  console.log('FAIL:');
  for (const e of errs) console.log(`  ✗ ${e}`);
  process.exit(1);
}
console.log('MOV-002/MOV-003/MOV-005 quadratic fix: identical findings on long-line fixtures (real multiply/divide/auth-discard still fire, clean stays clean); every operand position that reads a long name is pinned in both directions (safe reads 0, unsafe reads 1) at 120/128/129/140/200 characters; 40k-digit/40k-char fixtures complete well inside generous timing tripwires; MOV-005 receiver-syntax name lookup anchored; every rule file present is swept against thirteen long-identifier shapes including parameter-list positions; MOV-001/MOV-012 parameter-list quadratics closed');
process.exit(0);
