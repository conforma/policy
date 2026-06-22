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
make ci                      # Full CI: test + acceptance + fmt-check + lint + opa-check + conventions-check + generate-docs
make generate-docs           # Regenerate Antora docs from annotations (commit changed files)
```

Single test via the CLI: `ec opa test ./policy -r <test_name>`

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

## Architecture (non-obvious parts)

**Collections** (`policy/*/collection/`) group related rules. Each collection imports specific policy
packages. Examples: `minimal` (basic validation), `slsa3` (SLSA Level 3), `redhat` (Red Hat-specific).
When adding a new rule, you must add it to the appropriate collection(s) or it won't be evaluated.

**SLSA dual-format:** The library in `policy/lib/tekton/` normalizes both SLSA v0.2 and v1.0
attestation formats. Policies consume the normalized form — don't branch on SLSA version in rules.

**Rule data** lives in `example/data/` (required tasks, trusted task bundles, known RPM repos).
These files have `effective_on` dates — rules with future dates are warnings, not failures.

## Common Change Patterns

| Change | Pattern to follow |
|--------|-------------------|
| Add a new release policy rule | `policy/release/` (rule + _test + add to collection) |
| Add a new pipeline policy rule | `policy/pipeline/` |
| Add a shared library function | `policy/lib/` (must have test coverage) |
| Fetch and parse an OCI blob as JSON | Use `oci.parsed_blob(ref)` from `data.lib.oci`, not `json.unmarshal(ec.oci.blob(ref))` directly. A Regal lint rule (`prefer-parsed-blob`) enforces this. |

## Rego Evaluation Model (for AI reviewers)

Rego is a declarative policy language (Datalog-inspired), not imperative code.
Understanding its evaluation model is critical for accurate code review.

### Evaluation Semantics

- Multiple rule bodies with the same name are **disjunctions** (OR). Conditions
  within a body are **conjunctions** (AND).
- Rules evaluate to `true` or `undefined` — there are no "return values" or
  control flow. Do not describe Rego rules as "returning" values or having a
  "public API" in the imperative sense.
- There is no call/return mechanism, no early returns, and no try/catch.

### Testing Idioms

- Testing each conjunction term independently is **sufficient and idiomatic**.
  Because rules compose declaratively (AND/OR), full coverage of individual
  clauses provides equivalent assurance to testing the composed rule.
- Do not request integration tests through higher-level rules (e.g.,
  `is_registry_dependency`) when individual clause tests exist and `make test`
  enforces 100% coverage.
- This repo enforces 100% test coverage via `make test`. If coverage is met,
  the tests are sufficient.

### Idiomatic Patterns to Suggest

When reviewing Rego code, prefer these idiomatic patterns over verbose alternatives:

| Instead of | Suggest |
|------------|---------|
| Explicit iteration / index-based loops | `some x in collection` |
| Manual key-existence checks | `object.get(obj, key, default)` |
| Chained equality (`x == "a"; x == "b"`) | `x in {"a", "b"}` |
| Verbose negation | `not rule_name` |

### What NOT to Suggest

- **Early returns or control flow** — Rego has none.
- **Try/catch or error handling** — Rego has no exceptions.
- **Null guards for parser-guaranteed keys** — if the input schema guarantees a
  key exists (e.g., from `ec.oci.blob` or SLSA attestation structure), do not
  suggest defensive key-existence checks.
- **Integration tests through higher-level rules** — when individual clause tests
  exist and coverage is 100%, this adds no value and reflects imperative testing
  assumptions.

## PR Conventions

Conventional commits are encouraged. Run `make ci` before pushing. CI runs on every PR via
`.github/workflows/pre-merge-ci.yaml`. Policy bundles are published on merge to main via
`.github/workflows/push-bundles.yaml`.

