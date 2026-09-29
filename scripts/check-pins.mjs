#!/usr/bin/env node
/**
 * check-pins.mjs — verifies every reference to this action, anywhere in
 * the tracked tree, is pinned to the RELEASE commit package.json's own
 * "version" field names.
 *
 * Why this exists: the example workflows drifted to a PRIOR release's
 * SHA after a version bump -- three times now (`7daae46`, `babc3fa`,
 * and the pair this file was written to fix), and nothing re-checked it
 * after the first two. A hard-coded file list rots the day a third
 * example is added — the reference set below is DERIVED from
 * `git ls-files`, never enumerated by hand.
 *
 * Usage:
 *   node scripts/check-pins.mjs
 *
 * Prints one line per reference found (file:line, OK or the specific
 * mismatch) and a summary. Exit codes match this repo's own documented
 * contract (README.md's "Exit codes" table, the one `scripts/lint.mjs`
 * and `scripts/check-coverage.mjs` already share):
 *   0 = every reference found checks out
 *   1 = at least one reference is pinned to the wrong thing
 *   2 = a broken precondition -- the release tag itself does not
 *       resolve (package.json's version has no matching tag yet: this
 *       is expected mid-release, between "bump the version" and "cut
 *       the tag" in RELEASE.md's own ordering, so it is reported as a
 *       precondition failure, never mistaken for exit 1's "a pin
 *       drifted")
 *   3 = the tool ran but verified nothing -- no reference to the action
 *       was found anywhere in the tracked tree at all, which for a
 *       checker whose whole job is "did every found reference check
 *       out" is a vacuous pass wearing exit 0's clothes if left
 *       unguarded. This DOES mean a legitimately reference-free tree
 *       (a stripped fork, a vendored copy with no example workflows)
 *       goes red -- accepted here, because this repo's own README.md
 *       always carries one; the check is now also asserting "this repo
 *       documents its own action," which is worth saying once, here.
 */
import { readFileSync } from 'fs';
import { execFileSync } from 'child_process';

// The literal owner/repo this checker looks for is assembled from two
// halves rather than written as one string -- writing the whole
// "owner/repo@" address as a literal here would make THIS file's own
// source text match its own scan (this file is tracked too), which
// would misreport itself as a reference to classify.
const OWNER = 'talongate';
const REPO_NAME = 'move-test-gen';
// An optional `/<subpath>` between the repo name and `@` -- GitHub
// resolves `owner/repo/some/dir@ref` as a reusable action living in a
// subdirectory of this same repo, and it is meant to move in lockstep
// with the same release. Missing this made such a reference invisible
// to the scan below rather than merely permissive about it.
const REF_PREFIX = `${OWNER}/${REPO_NAME}`;
// The reference itself never contains whitespace (a YAML `uses:` value,
// or a bare address in prose) -- stopping at `#` too, not only
// whitespace, so `@<sha># v1.6.1` (a trailing comment with no space
// before it) captures the SHA cleanly instead of swallowing the `#` and
// everything after it into one unrecognizable token; TRAILING_COMMENT_RE
// below still finds that comment independently, against the whole line.
// The capture may be EMPTY (`*`, not `+`): `...@# v1.6.1` has no ref at
// all, and requiring one character made such a line invisible to the
// scan instead of reported. An empty token falls through classifyRef to
// "unrecognized". Cost: a bare `<owner>/<repo>@` in prose with nothing
// after it is now flagged too; that shape has no innocent reading here.
const REF_RE = new RegExp(`${REF_PREFIX.replace(/\//g, '\\/')}(?:\\/[^\\s@]+)?@([^\\s#]*)`, 'g');
const SHA_RE = /^[0-9a-f]{40}$/i;
// The core `vX.Y.Z` is captured on its own; an optional SemVer
// pre-release/build suffix (`-beta.1`, `+build.5`) is recognized as part
// of the TAG SHAPE so such a reference is compared by version and
// reported as a precise mismatch, rather than falling into the
// catch-all "neither a SHA nor a tag" bucket with a message that names
// the wrong problem.
const TAG_RE = /^v(\d+\.\d+\.\d+)(?:[-+][0-9A-Za-z.-]+)?$/;
// A trailing `# vX.Y.Z` comment on the SAME line as a reference,
// anchored to end-of-line so it only matches the comment that actually
// follows THIS reference, never an unrelated `#` earlier on the line.
const TRAILING_COMMENT_RE = /#\s*v(\d+\.\d+\.\d+)\s*$/;

/**
 * Trailing punctuation a human naturally follows a reference with in
 * prose or markdown, stripped before classifying: a sentence-ending
 * period, a comma before "or", a closing paren/bracket, a backtick or
 * quote closing an inline code span, or `**` closing bold. None of
 * these can appear inside a genuine SHA ([0-9a-f]) or tag
 * (vX.Y.Z[-+...]), so stripping them never turns a real mismatch into a
 * false OK.
 *
 * The one accepted trade, named rather than silently taken: this also
 * forgives a genuinely MALFORMED YAML value like `uses: ...@v1.6.1)` --
 * an unbalanced paren that should not compile as a workflow at all. YAML
 * itself does not produce that shape from valid `uses:` syntax, and the
 * alternative (leaving every markdown mention of this action flagged
 * red on correct documentation) is the worse failure for a hygiene
 * checker: a gate that fires on compliant work teaches its reader to
 * ignore it.
 */
function stripTrailingPunctuation(token) {
  return token.replace(/[.,;:)\]`*"']+$/, '');
}

/**
 * Read package.json's declared version and resolve it to the tag's
 * commit. Throws (never returns a partial/empty result) if the tag does
 * not exist -- a version bump with no matching tag means there is no
 * release SHA to check anything against, so the whole run is void, not
 * merely one finding short. main() maps this to exit 2, per the file
 * header's own exit-code contract.
 */
function readReleaseInfo() {
  const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
  const version = pkg.version;
  if (!version) throw new Error('package.json has no "version" field');
  const tag = `v${version}`;
  let sha;
  try {
    // `^{commit}` peels an annotated tag to the commit it points at; a
    // lightweight tag already IS the commit, and peeling one is a no-op.
    // `stdio: ['ignore', 'pipe', 'pipe']` -- Node's execFileSync default
    // still lets a failing child's stderr print DIRECTLY to our own
    // stderr (measured: git's own "fatal: ambiguous argument..." leaks
    // through alongside the one clean line below) even though it is
    // ALSO captured into err.stderr for the catch block. Suppressing the
    // direct pass-through keeps the surface to the one line the catch
    // block below prints -- the same "loud but not a stack trace" bar
    // this file's whole header exists to hold.
    sha = execFileSync('git', ['rev-parse', `${tag}^{commit}`], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  } catch (err) {
    // This catch sees EVERY way `git rev-parse` can fail, not only a
    // missing tag (not a repo, git absent, a locked or corrupt repo), so
    // the usual-cause explanation is a hypothesis and git's own first
    // line rides beside it as the evidence -- still one line.
    const said = String(err.stderr || '').trim().split('\n')[0] || err.code || 'no output';
    throw new Error(
      `tag ${tag} does not resolve to a commit -- package.json declares version ${version}; the usual causes are a checkout without tags (needs fetch-depth: 0) or a version bumped before the tag was cut (see RELEASE.md's own ordering); git said: ${said}`,
      { cause: err },
    );
  }
  return { version, tag, sha };
}

/** git's own binary heuristic: a NUL byte anywhere in the content. */
function isBinary(buf) {
  return buf.includes(0);
}

/**
 * Every tracked reference to the action, derived from `git ls-files`
 * rather than a hard-coded list of "the two example workflows" -- see
 * the file header for why a derived set is the entire point.
 */
function findReferences() {
  const files = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' })
    .split('\0')
    .filter(Boolean);

  const refs = [];
  for (const file of files) {
    let buf;
    try {
      buf = readFileSync(file);
    } catch {
      // Tracked in the index but not present on disk (a submodule
      // gitlink, or a path deleted-but-not-yet-committed) -- not a real
      // file to scan, and not this checker's job to diagnose.
      continue;
    }
    if (isBinary(buf)) continue;
    const lines = buf.toString('utf8').split('\n');
    for (let i = 0; i < lines.length; i++) {
      REF_RE.lastIndex = 0;
      let m;
      while ((m = REF_RE.exec(lines[i]))) {
        refs.push({ file, line: i + 1, ref: stripTrailingPunctuation(m[1]), lineText: lines[i] });
      }
    }
  }
  return refs;
}

/**
 * Classify one found reference against the release info from
 * readReleaseInfo(). Three shapes, per the file header's own spec:
 *   - a 40-hex SHA, optionally with a trailing `# vX.Y.Z` comment
 *   - a `vX.Y.Z` tag, optionally with a SemVer pre-release/build suffix
 *   - anything else -- a branch name, `@main`, a short SHA -- reported
 *     as unpinned/unrecognized, which counts as a failure: an
 *     unrecognized reference cannot be verified as the release, so it
 *     has not "checked out" per this file's own exit contract.
 *
 * The trailing-comment check runs ONCE, before the SHA/tag split, and
 * applies to BOTH branches -- it used to run only inside the SHA branch,
 * so a stale `# vX.Y.Z` note beside a genuinely correct TAG reference
 * (`uses: ...@v1.6.1 # v1.5.0`) passed silently. A stale annotation
 * beside a correct pin is exactly the "docs say one thing, the pin says
 * another" confusion this checker exists to end.
 *
 * The comment is read from the whole line, so on a line carrying two
 * references it applies to both. Deliberate: a stale version note on a
 * documentation line is a defect whichever reference it sits beside, and
 * a `uses:` line in a workflow never carries two.
 */
function classifyRef(ref, release) {
  const token = ref.ref;
  const commentMatch = ref.lineText.match(TRAILING_COMMENT_RE);
  const commentOk = !commentMatch || commentMatch[1] === release.version;
  const commentSuffix = commentMatch
    ? (commentOk
      ? `, trailing # v${commentMatch[1]} agrees`
      : `, but its trailing comment says v${commentMatch[1]} while package.json says v${release.version}`)
    : '';

  if (SHA_RE.test(token)) {
    if (token.toLowerCase() !== release.sha.toLowerCase()) {
      return { ok: false, reason: `SHA ${token} does not match the release SHA ${release.sha} (${release.tag})` };
    }
    return commentOk
      ? { ok: true, reason: `OK (SHA${commentSuffix})` }
      : { ok: false, reason: `SHA matches${commentSuffix}` };
  }

  const tagMatch = TAG_RE.exec(token);
  if (tagMatch) {
    // Compare the WHOLE token against release.tag, never only the
    // captured X.Y.Z core: TAG_RE recognizes a pre-release/build suffix
    // as part of the SHAPE (so it is reported with a precise message
    // instead of falling into "unrecognized"), but `v1.6.1-beta.1` is a
    // DIFFERENT git ref from `v1.6.1` and can point at a different
    // commit -- comparing cores alone would silently treat them as the
    // same pin, which is the exact class of mis-verdict this file
    // exists to catch, just moved one level up. Caught by running this
    // very case before shipping it, not reasoned about.
    if (token !== release.tag) {
      return { ok: false, reason: `tag ${token} does not match package.json's version ${release.tag}` };
    }
    return commentOk
      ? { ok: true, reason: `OK (tag ${token}${commentSuffix})` }
      : { ok: false, reason: `tag matches${commentSuffix}` };
  }

  return { ok: false, reason: `unpinned/unrecognized reference "${token}" -- neither a 40-hex SHA nor a vX.Y.Z tag` };
}

function main() {
  let release;
  try {
    release = readReleaseInfo();
  } catch (err) {
    // Per the file header's exit-code contract: a broken precondition
    // is exit 2, never the raw stack trace an unhandled throw would
    // otherwise print at exit 1 -- exit 1 is reserved for "a pin
    // drifted", and this is a different failure a maintainer must be
    // able to tell apart from that at a glance.
    console.error(`check-pins: cannot determine the release to check against -- ${err.message}`);
    process.exitCode = 2;
    return;
  }

  const refs = findReferences();

  console.log(`check-pins: package.json version ${release.version} -> ${release.tag} = ${release.sha}`);

  if (refs.length === 0) {
    // Exit 3 ("the tool could not run and produced no verdict"), not 0:
    // this checker's whole job is "did every FOUND reference check out",
    // and with none found there is nothing to verdict on -- a green 0/0
    // here is a vacuous pass, not evidence of anything pinned correctly.
    console.log(`check-pins: no references to ${REF_PREFIX}@<ref> found in the tracked tree -- nothing was verified`);
    process.exitCode = 3;
    return;
  }

  let failures = 0;
  for (const ref of refs) {
    const verdict = classifyRef(ref, release);
    console.log(`${ref.file}:${ref.line} ${verdict.ok ? 'OK' : 'MISMATCH'} -- ${verdict.reason}`);
    if (!verdict.ok) failures++;
  }

  console.log(`check-pins: ${refs.length - failures}/${refs.length} references OK`);
  process.exitCode = failures === 0 ? 0 : 1;
}

main();
