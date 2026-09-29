# gate-selftest — the scorer's own regression suite

The eval lab trusts `scripts/check-coverage.mjs` as its judge. This folder is why
that trust is earned: every parser trap found during the five review rounds
(2026-07-14/15) is pinned here as a case with expected output.

Run from the repo root:

```bash
node eval/gate-selftest/run.mjs
```

All green = the scorer still catches everything it ever caught. Run it before
trusting any gate change, and in CI.

| Case | Pins |
|---|---|
| 01-gauntlet | 11 assert/abort sites through every parser trap: comma-in-condition, trailing comments, `//` and `)` inside string literals, three multiline styles, inline-comment abort. One true unpaired (E_LOCKED), exit 1. |
| 02-wildcard-no-inflate | A bare `#[expected_failure]` is reported as unscoped and does NOT inflate coverage. |
| 03-disabled-test-ignored | A commented-out `#[expected_failure(...)]` attribute does not count as coverage. |
| 04-shared-code-warning | Two functions sharing one abort code → the shared-code warning fires. |
| 05-known-tail-one-line | KNOWN LIMITATION pinned on purpose: two asserts on one line — the greedy regex sees only the last. If this case ever fails by finding both, the limitation was fixed: update the README and re-pin. |
| 06-survivor-classify | The `classify.mjs` pure function: redundant drop-assert pair → suspected-equivalent evidence; solo survivors → no evidence; zero survivors → empty. |
| 07-scope-filter | The `--scope` flag: mutations only applied to target files, non-target files untouched in Layer 2. |
| 08-baseline-zero-tests | Baseline 0-tests warning: `--mutate` on an empty tests dir must warn and exit 1, not silently pass. |
| 09-scope-pure-fn | The `scope-filter.mjs` pure function: only files ending with scope entries pass through. |
| 10-testability-check | Testability pre-flight: modules with CoinMetadata + no `#[test_only]` warn; modules with constructors pass. |
| 11-lint-rules | Nine of the lint rules (MOV-001, MOV-002, MOV-003, MOV-004, MOV-005, MOV-006, MOV-008, MOV-011, MOV-012; MOV-013 is pinned by case 23): synthetic Move source, no sui needed. Pins positive detection, false-positive suppression, and test-function skip for each rule. |
| 12-mov001-exemptions | MOV-001's name-based exemption list (`init`, `test_*`, `*_test`, `testing`, `destroy`) is pinned exactly — nothing else stops it from being widened or narrowed by accident, and a widened list is a silent gate bypass. Also pins that the exemption is name-based: `init` is skipped whatever it does. |
| 13-lint-endtoend | Case 11 covers each rule's `check()` directly, not what's around it. This spawns the real CLI twice — once against a tree with a HIGH finding, once against a clean tree — and asserts the exit code both ways, covering `lint.mjs`'s rule discovery/count and `check-coverage.mjs`'s severity-to-exit mapping. |

## Known limitations

- **Two asserts on one line** — the greedy regex sees only the last abort code. Case 05 pins this.
- **Multi-line attributes** — `#[expected_failure(...)]` split across lines is not detected. Keep attributes on one line.
- **Mutation testing** requires `sui` CLI installed locally. Layer 1 (assert pairing) works anywhere.
- **Abort code pairing** is by error constant name, not by which function throws it. If two functions use the same error constant, one test covers both — the checker warns about this but does not flag it as unpaired.

What this does **not** prove: Layer 2 (`--mutate`) behavior — that path needs a
real `sui` CLI and is field-verified separately (see the review thread record).
