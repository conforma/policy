# Conforma Policies

Rego policies for validating container image attestations, pipeline definitions, and Tekton tasks.
Evaluated by the [Conforma CLI](https://github.com/conforma/cli) using OPA. Bundled as OCI artifacts.

## Build & Test

```bash
make test                    # Run all tests (verbose, 100% coverage enforced)
make TEST="pattern" test     # Run tests matching regex
make coverage                # Show uncovered lines
make fmt                     # Format rego (run before every commit)
make lint                    # Regal linter + license headers
make ci                      # Full CI: quiet-test + acceptance + opa-check + conventions-check + fmt-check + lint + regal-test + generate-docs
make generate-docs           # Regenerate Antora docs from annotations (commit changed files)
```

Single test via the CLI: `ec opa test ./policy -r <test_name>`

## Single-File Verification

```bash
regal lint path/to/file.rego         # Lint a single Rego file (fast)
opa check --strict path/to/file.rego  # Parse/type-check a single Rego file (matches CI strict mode)
```

## Key Conventions

- **100% test coverage is enforced.** Every `.rego` file needs a `_test.rego` file. CI fails otherwise.
- **Run `make fmt` before committing.** CI checks formatting.
- **Run `make generate-docs` after changing policy annotations.** Commit the regenerated files.
- All tools (ec, opa, conftest, regal) run via `go run` with versions pinned in go.mod — no local installs needed.
- Tests run network-isolated when `unshare` is available.

## Policy Annotations

Every policy rule requires METADATA annotations. Missing or malformed annotations fail `make conventions-check`.

```rego
# METADATA
# title: Short rule name
# description: What the rule validates
# custom:
#   short_name: machine_readable_identifier
#   failure_msg: User-facing error message with %s interpolation
```

## Architecture (design rationale and non-obvious parts)

**Collections** (`policy/*/collection/`) group related rules. Examples: `minimal` (basic validation),
`slsa3` (SLSA Level 3), `redhat` (Red Hat-specific). New rules declare membership via the
`collections:` key in their METADATA annotation — see existing rules in `policy/release/` for the pattern.

**SLSA dual-format:** The library in `policy/lib/tekton/` normalizes both SLSA v0.2 and v1.0
attestation formats. Policies consume the normalized form — don't branch on SLSA version in rules.

**Rule data** lives in `example/data/` (required tasks, trusted task bundles, known RPM repos).
These files have `effective_on` dates — rules with future dates are warnings, not failures.

**Design docs** in `design/` capture non-obvious design rationale, cross-repo knowledge, and
architectural constraints that aren't derivable from the code. Check there before reverse-engineering
a subsystem.

## Rego Evaluation Model (for AI reviewers)

Rego is a declarative policy language (Datalog-inspired), not imperative code:
- Multiple rule bodies with the same name are **disjunctions** (OR). Conditions within a body are
  **conjunctions** (AND).
- Rules can define partial sets (`deny contains ...`), complete values (`allowed := true`), or
  functions (`f(x) := y`). `default` and `else` provide declarative fallback selection — not
  imperative control flow.
- Focused tests of individual clauses are preferred. Integration tests through higher-level rules
  (e.g., testing `deny`/`warn` output) are appropriate when composition affects behavior — bindings,
  aggregation, fallback selection, or final violation output.
- Prefer `some x in collection` over explicit iteration, `object.get(obj, key, default)` over
  key-existence checks, and `x in {a, b}` over chained equality.
- Do NOT suggest imperative patterns that Rego does not provide: early returns, try/catch, or
  exception handling. These concepts do not exist in Rego.

## Common Change Patterns

- **Add a release policy rule:** follow the pattern in `policy/release/attestation_type/attestation_type.rego` (rule + `_test.rego` in a subdirectory, declare `collections:` in METADATA)
- **Add a pipeline policy rule:** follow the pattern in `policy/pipeline/required_tasks.rego`
- **Add a shared library function:** see `policy/lib/tekton/` for reference implementation (must have test coverage)
- **Fetch and parse an OCI blob:** use `oci.parsed_blob(ref)` from `data.lib.oci`, not `json.unmarshal(ec.oci.blob(ref))` directly. A Regal lint rule (`prefer-parsed-blob`) enforces this
- **Add a new collection:** follow the pattern in `policy/release/collection/` — import specific policy packages

## Review Checklist for New Policy Rules

- **`effective_on` date required:** New deny/warn rules MUST include an `effective_on` date in their
  METADATA annotation (under `custom:`) to provide a migration window before enforcement begins.
  Rules without `effective_on` enforce immediately on deployment, which can break existing builds
  without warning. Look for the annotation block above each new `deny contains` or `warn contains`
  rule and verify it includes `effective_on: <future RFC 3339 date>`. See existing rules in
  `policy/release/` for the pattern. Rule data entries in `example/data/` YAML files (e.g.,
  `required_tasks.yml`, `trusted_tekton_tasks.yml`) also use `effective_on` for data-driven rules.
- **Collection membership:** New rules must declare membership in the appropriate collection(s) via
  the `collections:` key in their METADATA annotation. See existing rules in `policy/release/` for
  the pattern.
- **Test coverage:** Every new rule needs tests in a corresponding `_test.rego` file. CI enforces
  100% coverage.

## Testing New Helper Functions

When a PR introduces a new public helper function in `policy/lib/`, it must have
direct unit tests in the corresponding `_test.rego` file — not just indirect
coverage through consuming rules. Direct tests should exercise:
- Each logical branch of the function
- Edge cases (empty strings, non-string values, boundary conditions)
- The function's contract independent of any specific caller

100% coverage through indirect tests alone is not sufficient for functions with
multiple logical branches.

## PR Conventions

Conventional commits are encouraged. Run `make ci` before pushing. CI runs on every PR via
`.github/workflows/pre-merge-ci.yaml`. Policy bundles are published on merge to main via
`.github/workflows/push-bundles.yaml`.

