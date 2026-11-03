/**
 * MOV-001: Missing access control on state-modifying public functions.
 *
 * Flags public functions that take &mut parameters (state modification)
 * but have no capability parameter (AdminCap, OwnerCap, or any *Cap type).
 *
 * Why it matters: Kriya's update_pool was callable by anyone because it
 * lacked an access control check. Any public function that mutates shared
 * state without a capability gate is an open door.
 *
 * Exceptions: init(), test_only functions, view functions (no &mut on
 * domain objects), and functions whose only &mut is TxContext.
 */

const RULE_ID = 'MOV-001';
const SEVERITY = 'HIGH';
const TITLE = 'public function modifies state without capability check';

/**
 * @param {string} source — file content
 * @param {string} filename
 * @returns {Array<{rule, severity, file, line, message}>}
 */
export function check(source, filename) {
  const findings = [];
  const lines = source.split('\n');

  let testOnlyNext = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (trimmed.startsWith('//')) continue;

    if (/#\[test_only\]/.test(trimmed)) {
      testOnlyNext = true;
      // same-line item (#[test_only] use ...) consumes the attribute immediately
      const afterAttr = trimmed.replace(/^#\[test_only\]\s*/, '');
      if (/\b(fun|use|struct|const|entry)\b/.test(afterAttr)) testOnlyNext = false;
      continue;
    }

    const isTestOnly = testOnlyNext;
    // clear the flag on ANY item keyword, not just fun — #[test_only] on a use/struct/const
    // must not carry over to the next function (advisory #7, GHSA-5499)
    if (testOnlyNext && /\b(fun|use|struct|const|entry)\b/.test(trimmed)) testOnlyNext = false;

    const fnMatch = trimmed.match(/^public(?:\s*\((?:package|friend)\))?\s+(?:entry\s+)?fun\s+(\w+)(?:<[^>]*>)?\s*\(([^)]*)\)/);
    if (!fnMatch) {
      const startMatch = trimmed.match(/^public(?:\s*\((?:package|friend)\))?\s+(?:entry\s+)?fun\s+(\w+)(?:<[^>]*>)?\s*\(/);
      if (startMatch) {
        let params = '';
        let parenDepth = 0;
        let seenOpenParen = false;
        for (let j = i; j < Math.min(i + 10, lines.length); j++) {
          // Strip trailing comments per accumulated line -- otherwise a
          // comment mentioning "Cap" (e.g. "// AdminCap checked upstream")
          // gets matched by hasCap's regex below as if it were a real
          // capability parameter, silencing a genuinely unguarded function.
          const codeOnly = lines[j].replace(/\/\/.*$/, '');
          params += codeOnly + '\n';
          // Track real paren depth rather than stopping at the first `)` --
          // a `public(package)`/`public(friend)` prefix closes its OWN paren
          // before the parameter list's opening paren is even reached, so
          // "any )" stops accumulation one line too early and the real
          // parameter list (and the closing `)` fullMatch needs) is never
          // captured at all.
          const opens = (codeOnly.match(/\(/g) || []).length;
          const closes = (codeOnly.match(/\)/g) || []).length;
          parenDepth += opens - closes;
          if (opens > 0) seenOpenParen = true;
          if (seenOpenParen && parenDepth <= 0) break;
        }
        // Same visibility-modifier alternative as the primary regex above --
        // without it, a wrapped `public(package) fun`/`public(friend) fun`
        // signature never matches here and the function is silently never
        // checked at all (contradicts CHANGELOG.md's public(package) claim).
        const fullMatch = params.match(/public(?:\s*\((?:package|friend)\))?\s+(?:entry\s+)?fun\s+(\w+)(?:<[^>]*>)?\s*\(([^)]*)\)/);
        if (fullMatch) {
          checkFunction(fullMatch[1], fullMatch[2], i + 1, filename, findings, isTestOnly);
        }
      }
      continue;
    }

    checkFunction(fnMatch[1], fnMatch[2], i + 1, filename, findings, isTestOnly);
  }

  return findings;
}

function checkFunction(name, params, lineNo, filename, findings, isTestOnly) {
  if (isTestOnly) return;
  if (name === 'init' || name.includes('testing') || name.includes('destroy')) return;
  if (name.startsWith('test_')) return;
  if (name.endsWith('_test')) return;

  // does it take &mut on something other than TxContext?
  const hasMut = /&mut\s+(?!TxContext)(?!tx_context)/.test(params);
  if (!hasMut) return;

  // does it have a capability or key parameter? The rule is: some word in
  // the parameter list ends in `Cap` (or `Key`) and either IS that bare
  // word or has an uppercase letter before it -- `AdminCap`, `TreasuryCap`,
  // `Cap`; not `xCap`, not `Capx`.
  //
  // This is not written as a regex (`[A-Z]\w*Cap\b`) because that is
  // O(n^2): against a long ALTERNATING-CASE identifier (`AaAaAa...`),
  // `[A-Z]` matches at every other offset and each match rescans the rest
  // of the run for a `Cap` that is not there (an all-lowercase run does not
  // trigger it; only case alternation multiplies the start positions).
  // Capping the `\w*` (say `{0,127}`) removes the blow-up but changes the
  // answer, because this is a BOOLEAN: once more than 127 characters sit
  // between the uppercase and the `Cap`, no start position can reach it,
  // and a function that HAS its capability gate reads as missing one. A
  // bound on a boolean has to give up one of the two answers, so none is
  // used here.
  //
  // Instead: a plain literal test first (linear, and false for almost every
  // real parameter list), then the rule above evaluated per word-run.
  // `/\w+/g` visits each run once, and `endsWith` plus a single uppercase
  // scan of the same run are linear in it, so the whole test is linear in
  // the parameter string and gives the regex's answer at any length.
  const hasCap = /Cap\b|Key\b/.test(params) &&
    (params.match(/\w+/g) || []).some(word => {
      for (const suffix of ['Cap', 'Key']) {
        if (word.endsWith(suffix) && (word.length === suffix.length || /[A-Z]/.test(word.slice(0, -suffix.length)))) return true;
      }
      return false;
    });
  if (hasCap) return;

  // does it have a witness parameter that implies auth? A `key`/`_key`
  // param only counts when its TYPE isn't a plain Move primitive -- a
  // generic type parameter (the `_key: T` pattern the selftest pins,
  // where only a caller holding a real `T` value can pass one) carries
  // some signal, but `key: u64`/`_key: bool`/etc name the type outright
  // and provide none: any caller can write a literal. Previously any
  // type at all exempted the function purely because the param was
  // named `key`/`_key`.
  const PRIMITIVE_PARAM_TYPES = /^(u8|u16|u32|u64|u128|u256|bool|address|signer|vector)\b/;
  const keyParamMatch = params.match(/\b_?key\s*:\s*(\w+)/);
  const hasWitness = /Witness\b/.test(params) ||
    (keyParamMatch !== null && !PRIMITIVE_PARAM_TYPES.test(keyParamMatch[1]));
  if (hasWitness) return;

  // does it have a Version/VersionGate parameter (contract version check as access gate)?
  const hasVersion = /\bVersion\b|\bVersionGate\b/.test(params);
  if (hasVersion) return;

  // does it take user-owned assets (DeFi user-facing — permissionless by design)?
  // Coin<T>, LP tokens, receipts passed by value act as implicit access control
  const hasUserAsset = /Coin<|Balance<|LPToken|LpToken|LP_Token|Receipt|FlashLoan/.test(params);
  if (hasUserAsset) return;

  // does it only mutate a user-owned token/NFT (self-modification pattern)?
  // word boundaries prevent "PositionManager" (shared object) from matching "Position" (user-owned NFT)
  const mutParams = params.match(/&mut\s+(?!TxContext)(?!tx_context)\w+/g) || [];
  const onlySelfMut = mutParams.every(p => /\bToken\b|\bNFT\b|\bTicket\b|\bReceipt\b|\bPosition\b/.test(p));
  if (onlySelfMut && mutParams.length > 0) return;

  findings.push({
    rule: RULE_ID,
    severity: SEVERITY,
    file: filename,
    line: lineNo,
    message: `${TITLE}: \`${name}\` takes &mut but no capability parameter`,
  });
}

export const meta = { id: RULE_ID, severity: SEVERITY, title: TITLE };
