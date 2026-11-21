# move-test-gen

![gate-selftest](https://github.com/talongate/move-test-gen/actions/workflows/gate.yml/badge.svg)

> **Using this as a GitHub Action?** Jump to [CI integration](#ci-integration).

An [Agent Skill](https://github.com/agentskills/agentskills) that generates edge-case test suites for Sui Move functions.

## What it does

Give it a Move module and it produces `#[test]` and `#[expected_failure]` functions covering:

- **Boundary values** — zero, one, max u64/u128, empty collections
- **Arithmetic edges** — multiplication overflow, division by zero, rounding direction
- **Access control** — missing capability, wrong capability type, post-transfer use
- **State machine** — wrong call order, double execution, unresolved hot potato
- **Economic** — fee evasion via dust amounts, first-depositor share inflation, rounding profit

Output is a `.move` test file targeting `sui move test`. The example in `examples/` includes a complete package with `Move.toml`, source module with `#[test_only]` helpers, and generated tests — run `cd examples && sui move test` to verify.

## Usage

Install via the skills CLI:

```
npx skills add talongate/move-test-gen
```

> `skills add` resolves against the default branch and carries no version, so
> it always installs the current `main` — including changes that are in no
> released tag. That is usually what you want for a Claude Code skill, which
> updates in place. If you need a fixed version, install from a tag instead of
> the branch, or use the GitHub Action, which is pinned by ref.

> **Windows note:** if PowerShell blocks `npx` with an execution-policy error,
> run `npx.cmd skills add talongate/move-test-gen` instead (stock PowerShell
> default, not a skill issue).

> **Always keep the `talongate/` prefix.** The bare package name
> (`npx move-test-gen`, without an owner) resolves to a placeholder on the
> npm registry that predates every security fix in this repo's history —
> it exists only so the name isn't squatted, and its own description still
> points at the pre-transfer org name. Every command on this page uses the
> full `talongate/move-test-gen` form on purpose; don't shorten it.

Or manually place it in your Claude Code environment:

```
skills/
└── move-test-gen/
    ├── SKILL.md
    ├── scripts/
    │   ├── check-coverage.mjs
    │   ├── classify.mjs
    │   ├── lint.mjs
    │   ├── move-parser.mjs
    │   ├── scope-filter.mjs
    │   ├── testability.mjs
    │   └── walk-dir.mjs
    ├── rules/
    │   └── mov-*.mjs            (every rule file, needed for --lint)
    └── references/
        └── patterns.md
```

The simplest correct instruction is to copy `scripts/`, `rules/` and
`references/` wholesale — `check-coverage.mjs` imports four sibling modules and
`lint.mjs` loads every `rules/mov-*.mjs` at run time.

Then ask Claude Code:

```
Generate edge-case tests for sources/vault.move
```

or:

```
The audit found a rounding issue in calculate_shares().
Generate regression tests that fail without the fix.
```

## Coverage checker

After generating tests, verify nothing was missed:

```bash
node scripts/check-coverage.mjs ./sources ./tests
```

This scans every `assert!` and `abort` in your source modules, every `#[expected_failure]` in your tests, and reports unpaired asserts — abort paths that have no corresponding failure test.

For stronger verification, add `--mutate`:

```bash
node scripts/check-coverage.mjs ./sources ./tests --mutate
```

Mutation testing injects deterministic bugs (flip a comparison, drop an assert) and checks whether your test suite catches them. If a mutation survives, the test that should have caught it is too weak.

By default, `--mutate` applies one mutation per operator per line. All 7 operators (flip `<`/`>`/`<=`/`>=`/`==`/`!=`, drop `assert!`) run exhaustively — every matchable line is tested.

## Security lint

The gate also includes `--lint` — security pattern detection for Sui Move:

```bash
node scripts/check-coverage.mjs ./sources ./tests --lint
```

| Rule | Severity | What it catches |
|------|----------|----------------|
| **MOV-001** | HIGH | `public fun` with `&mut` but no capability, key, or witness parameter |
| **MOV-002** | HIGH | `u64 * u64` without `u128` promotion before multiplication, or a left shift (`<<`) that silently discards the high bits on overflow |
| **MOV-003** | MEDIUM | Division by a variable with no prior `assert!(x != 0, ...)` |
| **MOV-004** | MEDIUM | `(expr as u64)` downcast from u128/u256 without overflow check |
| **MOV-005** | HIGH | Bool-returning auth call (`vector::contains`, `has`, `is_authorized`) result discarded — authorization runs but is never enforced |
| **MOV-006** | LOW | Same abort code used in `assert!` across 2+ public functions — callers cannot distinguish which function aborted |
| **MOV-008** | MEDIUM | `assert!(payment == required)` exact-equality check on a caller-controlled amount — dust/rounding/fee-on-transfer breaks it; use `>=` instead |
| **MOV-011** | HIGH | `public(package) entry` function — the `entry` modifier makes it callable via PTB from outside the package despite the `package` restriction |
| **MOV-012** | HIGH | Sender/caller identity taken as a plain `address` parameter instead of `tx_context::sender(ctx)` — spoofable by any PTB caller |
| **MOV-013** | HIGH | `#[spec_only]` public function compiles into production bytecode with zero access control — same class as the CDPM $300K drain |

Rules are pure functions in `rules/*.mjs`. The engine skips `#[test_only]` modules and `#[test]` function bodies automatically. MOV-002 and MOV-004 use a lightweight Move parser (`scripts/move-parser.mjs`) to track variable types through declarations, casts, and naming conventions — if an operand is known u128/u256, the finding is suppressed instead of relying on suffix heuristics.

MOV-001 recognizes several Sui Move access control idioms beyond `*Cap`: `Witness<T>`, `Version`, `*Key`, and user-asset parameters (`Coin<T>`, `Balance<T>`, LP tokens) that make a function intentionally permissionless. MOV-005 only flags bool-returning functions (not void functions like `verify()` that abort internally). MOV-006 filters lowercase variable names to avoid flagging parameters used as abort arguments.

**Lab-recorded** (eval scenarios with dated round records): SuiTears and Cetus IntegerMate. **Manual spot-checks** (run outside the lab, no round record): Kriya DEX, Scallop (172 files, 82→1 FP reduction), Bucket Protocol, Turbos CLMM, Typus Finance. MOV-005 catches the class of vulnerability reported in the Typus Finance incident (Oct 2025).

Or run lint standalone:

```bash
node scripts/lint.mjs ./sources
```

## What this proves — and what it doesn't

The coverage checker is a deterministic floor: it proves every assert has a matching `#[expected_failure]` test, and (with `--mutate`) that the generated tests actually compile and that the suite catches injected bugs. It does **not** prove a test asserts the right thing — that judgment stays with the reviewer.

> "Never let the floor pretend to be the ceiling."
> — [HetCreep](https://github.com/TheColliery/CoalWash), who framed this better than I could.

Generation can be probabilistic; the gate never is.

## Coverage targets

The skill aims for:

| Function type | Minimum tests |
|--------------|---------------|
| Arithmetic (multiply/divide) | 5 |
| Access-controlled | 3 |
| State-transition | 4 |
| Economic (fees/rates) | 6 |

## Exit codes

| code | meaning |
|---|---|
| `0` | clean |
| `1` | the gate failed — unpaired asserts, surviving mutants, or a lint finding at or above the threshold |
| `2` | usage error, or a sources/tests directory that cannot be read |
| `3` | the tool could not run and produced no verdict (for example `--mutate` was requested but the `sui` CLI is missing, or a lint run hit a `.move` file it could not read — such as an unterminated `/*` block comment) |

`130` and `143` are the usual SIGINT / SIGTERM codes.

**This table is one contract, honored identically by both `scripts/lint.mjs`
run standalone and `scripts/check-coverage.mjs ... --lint`** (the entry point
the GitHub Action runs) — both read the same `runLint()`, and an unreadable
file gets the same exit `3` and the same on-screen message either way.

A defect outranks a missing tool: if Layer 1 found something, the run exits `1`
even when `--mutate` could not run. The same precedence holds for an unreadable
file found by `--lint`, on either entry point: a real finding elsewhere in the
same run still exits `1`. Exit `3` means no verdict was reached, which is a
different thing from a verdict of "failed" and should usually be read as a
broken CI configuration rather than a broken pull request.

## Running on untrusted code

Layer 1 (assert pairing) and `--lint` **never execute or compile** the code they
read. They are regex and string analysis over the source text, so running them
on a pull request from a fork is no more dangerous than reading the diff.

`mutate: 'true'` is different. It invokes `sui move build` and `sui move test`
on the source under review, which means:

- the Move code in the pull request is compiled and its tests are run on your runner
- the `Move.toml` in the pull request decides which git dependencies get fetched

That is ordinary for any mutation-testing tool — you cannot mutation-test code
without running it — but it should be a deliberate choice rather than a
surprise. The shipped nightly example
(`examples/workflows/nightly-mutation.yml`) runs on a schedule against the
default branch for exactly this reason, and the pull-request example
(`examples/workflows/pr-gate.yml`) does not set `mutate` at all.

If you do want Layer 2 on pull requests, run it on `pull_request` (not
`pull_request_target`), keep `permissions: contents: read`, and do not expose
secrets to that job.

## Suppressing a finding

Three scopes, narrowest first.

```move
// move-test-gen-disable-next-line MOV-003
let ratio = total / divisor;          // this line only

// move-test-gen-disable MOV-001, MOV-005
module demo::legacy { ... }           // rest of the file
```

```bash
node scripts/check-coverage.mjs sources tests --lint --disable MOV-003,MOV-006
```

A comment pragma is used rather than a Move attribute: `#[allow(lint(...))]`
belongs to the compiler's namespace, so an unknown attribute there risks a
warning from `sui move build`, while a comment is invisible to it.

Suppressed findings are counted in the summary line, so a reviewer can tell
that something was silenced rather than never found.

## Known limitations

The checker is a regex-based parser, not a compiler. It handles the common patterns — including multi-line asserts, module-qualified aborts, and string literals with `//` — but edge cases exist:

- **Two asserts on one line** — the greedy regex sees only the last abort code. Pinned in selftest case 05.
- **Multi-line attributes** — `#[expected_failure(...)]` split across lines is not detected. Keep attributes on a single line.
- **Mutation testing** requires `sui` CLI installed locally. Layer 1 (assert pairing) works anywhere.
- **Abort code pairing** is by error constant name, not by which function throws it. If two functions use the same `EZeroAmount`, one `#[expected_failure]` test covers both — the checker warns about this but does not flag it as unpaired.

## CI integration

Use as a GitHub Action in any Sui Move repo — no install, no dependencies beyond Node:

```yaml
# .github/workflows/move-coverage.yml — runs on every PR
name: move-coverage
on: [pull_request]
jobs:
  coverage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: talongate/move-test-gen@v1.6.1
        with:
          sources: sources
          tests: tests
```

Layer 1 (assert pairing) runs in seconds with zero dependencies. For mutation testing, add `mutate: 'true'` and install `sui` — see [examples/workflows/nightly-mutation.yml](examples/workflows/nightly-mutation.yml) for a nightly schedule. For security lint, add `lint: 'true'`.

Or run the checker standalone:

```bash
npx talongate/move-test-gen sources tests
npx talongate/move-test-gen sources tests --mutate
```

## Eval lab

The skill is measured, not trusted: `eval/` holds a scenario lab that fires frozen
prompt templates at bait modules and scores every round with the gate — retirement
by saturation, dated records, figures never edited by hand. Five campaigns closed:
fixtures (53/53), honesty channel, real protocol (SuiTears), Layer 1 validation
(SuiTears + Cetus), and cross-family (DeepSeek vs GPT-5.5). 13 scenarios, 46
rounds. Full records: [eval/RESULTS.md](eval/RESULTS.md).

The lab's methodology — the retirement protocol, frozen templates, and the honesty-
channel assignment — is borrowed, with thanks, from
[HetCreep / TheColliery](https://github.com/TheColliery). Full lineage in the record.

## Pairs with

- Security audit agents (feed findings → generate regression tests)
- `sui move test --coverage` (fill gaps identified by coverage reports)
- CI pipelines (generate tests as part of PR review)

## Acknowledgements

Security audit by [@HetCreep](https://github.com/HetCreep), ongoing across several rounds — public issues and private advisories, tracked in the issue list and the Security tab. The audit caught gate bypasses, CI hardening gaps, and a supply-chain typosquat risk that was filed privately to protect the project.

## References

See [references/patterns.md](references/patterns.md) for the full catalog of Move-specific edge cases with code templates and rationale.
