---
name: move-test-gen
description: >
  WHEN: after an audit finding, after adding a public/entry function, when sui move
  coverage summary shows gaps, when a PR touches arithmetic or access control.
  WHAT: generates edge-case and adversarial Move test suites — boundary values,
  overflow/underflow, access-control violations, state-machine ordering.
  Also runs security lint (every rule in rules/, e.g. MOV-001 missing capability, MOV-002
  unchecked mul + bit-shift, MOV-003 div-by-zero, MOV-004 unsafe downcast, MOV-005
  discarded auth check, MOV-006 shared abort code, MOV-008 exact-equality payment
  assert, MOV-011 public(package) entry PTB bypass, MOV-012 spoofable sender
  address param) and mutation testing to verify test strength.
  Pairs well with security audit agents — feed it findings, it produces regression
  tests that fail without the fix.
---

# Move Test Generator

You generate exhaustive test cases for Sui Move functions. Your output is
compilable Move test code (`#[test]` and `#[expected_failure]`) that a developer
can drop into their `tests/` directory and run with `sui move test`.

You think like an attacker: for every function, you ask "what input breaks this?"

## When To Use This Skill

- After writing a new public/entry function — generate tests before merging
- After an audit finding — produce a regression test that fails without the fix
- When `sui move coverage summary` shows <100% on a function — fill the gaps
- When reviewing a PR that changes arithmetic, access control, or state transitions

## Process

### Step 1 — Read the Target

Read the target `.move` file(s). For each `public`, `public(friend)`, and `entry`
function, extract:

1. **Name and visibility**
2. **Parameters** — types, which are references (`&` vs `&mut`), which are capabilities
3. **Return type(s)**
4. **Abort conditions** — every `assert!` and implicit abort (arithmetic overflow, vector OOB)
5. **State mutations** — what fields change, in what order
6. **External calls** — does it call other modules? Which ones?

### Step 2 — Classify Each Function

Assign one or more categories:

| Category | What to test | Example |
|----------|-------------|---------|
| **ARITHMETIC** | overflow, underflow, division by zero, rounding direction | `amount * price / PRECISION` |
| **BOUNDARY** | zero, one, max u64/u128, empty vector, single element | `withdraw(0)`, `withdraw(MAX_U64)` |
| **ACCESS** | calling without required capability, wrong capability type | `admin_fn()` without `AdminCap` |
| **STATE** | wrong order of operations, double-call, call after destroy | `repay()` before `borrow()` |
| **ECONOMIC** | fee evasion, rounding profit, dust extraction | `deposit(1)` then `withdraw(1)` nets different amount |
| **REENTRANCY** | not applicable in Move (no callbacks), but test PTB composition | split across multiple PTB commands |

### Step 3 — Generate Tests

For each function, produce test functions following these rules:

**Naming**: `test_<function>_<category>_<case>`
```move
#[test]
fun test_withdraw_boundary_zero_amount() { ... }

#[test]
#[expected_failure(abort_code = vault::EInsufficientBalance)]
fun test_withdraw_boundary_exceeds_balance() { ... }
```

**Structure**: each test is self-contained:
```move
#[test]
fun test_deposit_arithmetic_max_u64() {
    // SETUP: create test objects
    let mut ctx = tx_context::dummy();
    let mut vault = vault::create_for_testing(&mut ctx);

    // ACT: call with edge-case input
    let coin = coin::mint_for_testing<SUI>(MAX_U64, &mut ctx);
    vault::deposit(&mut vault, coin);

    // ASSERT: verify postconditions
    assert!(vault::balance(&vault) == MAX_U64, 0);

    // CLEANUP: destroy test objects
    vault::destroy_for_testing(vault);
}
```

**Coverage targets per function:**

| Function type | Minimum tests |
|--------------|---------------|
| Arithmetic (multiply/divide) | 5: zero, one, normal, large, max |
| Access-controlled | 3: authorized, unauthorized, wrong-cap-type |
| State-transition | 4: happy path, wrong order, double call, after destroy |
| Economic (fees/rates) | 6: zero amount, dust, normal, large, fee boundary, rounding |

### Step 4 — Verify Completeness

After generating all tests:

1. List every `assert!` in the source — each one must have a corresponding `#[expected_failure]` test that triggers it
2. List every arithmetic operation — each must have an overflow boundary test
3. List every capability parameter — each must have an unauthorized-caller test
4. Count: at least 3 tests per public function, 5+ for functions that handle funds

### Step 5 — Output

Produce a single `.move` test file:

```
module <package>::<module>_tests {
    use <package>::<module>;
    use sui::test_scenario;
    use sui::coin;
    use sui::tx_context;

    // --- BOUNDARY TESTS ---
    // ... (grouped by category)

    // --- ARITHMETIC TESTS ---
    // ...

    // --- ACCESS CONTROL TESTS ---
    // ...

    // --- STATE MACHINE TESTS ---
    // ...

    // --- ECONOMIC TESTS ---
    // ...
}
```

Include a summary comment at the top:
```move
// Generated by move-test-gen
// Target: <module>::<function_list>
// Tests: N total (X boundary, Y arithmetic, Z access, W state, V economic)
// Expected failures: M
// Coverage targets: <list functions and expected coverage %>
```

## Quality Rules

1. **Every test must compile.** Do not use functions that do not exist. Check the module's public API before referencing helpers. If the module lacks `#[test_only]` constructors (e.g., `create_for_testing`), use `test_scenario` to create objects through the module's `init` function instead. Never assume a `_for_testing` helper exists — read the source first.
2. **No magic numbers without comments.** If a test uses `1_000_000_000`, comment that it is `1 SUI in MIST`.
3. **Realistic values.** Use amounts that make sense for the protocol (not `42` or `12345`). Read the module constants for fee rates, minimums, decimals.
4. **Test isolation.** Each test creates its own state. No shared mutable state across tests.
5. **Cleanup.** Every created object must be destroyed or transferred. Move's linear types enforce this — if a test does not compile due to unused values, you have a cleanup bug.

## What This Skill Does NOT Do

- Does not run tests (the developer runs `sui move test`)
- Does not fix bugs (use an audit-to-fix workflow for that)
- Does not generate fuzz inputs (deterministic edge cases only)
- Does not replace manual review (it catches known patterns, not novel logic bugs)

## References

See `references/patterns.md` for the full catalog of Move-specific edge cases and the rationale behind each test category.
