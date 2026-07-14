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
- **Test attestation mock patterns:** Tests for `test_attestation` require Sigstore/OCI mock
  infrastructure (referrer descriptors, SLSA provenance builders, verify mocks). See
  `policy/release/test_attestation/test_attestation_test.rego` and
  `policy/lib/intoto/trust_test.rego` for the canonical mock patterns.

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

**Dual test-result validation:** Test results are validated through two parallel paths that must
maintain feature parity:
- `policy/release/test/` validates pipeline task results (`TEST_OUTPUT` from SLSA provenance).
- `policy/release/test_attestation/` validates in-toto test-result attestations verified through
  Sigstore/SLSA provenance chains (via `policy/lib/intoto/trust.rego`).

When adding or modifying test result rules (e.g. a new result status, changed failure semantics),
both packages must be updated together.

**Trust verification chain:** `policy/lib/intoto/trust.rego` couples `lib.intoto`, `lib.sigstore`,
`lib.tekton`, and OCI builtins to verify that in-toto statements were produced by trusted pipelines.
The trust model is fail-closed: if blob fetching, JSON parsing, or type validation fails for a
referrer, that statement is silently excluded from `verified_statements` (no error is emitted).
Consumer deny rules in packages like `test_attestation` surface the absence as a policy violation.

## Common Change Patterns

| Change | Pattern to follow |
|--------|-------------------|
| Add a new release policy rule | `policy/release/` (rule + _test + add to collection) |
| Add a new pipeline policy rule | `policy/pipeline/` |
| Add a shared library function | `policy/lib/` (must have test coverage) |
| Fetch and parse an OCI blob as JSON | Use `oci.parsed_blob(ref)` from `data.lib.oci`, not `json.unmarshal(ec.oci.blob(ref))` directly. A Regal lint rule (`prefer-parsed-blob`) enforces this. |
| Add/modify test result validation | Update both `policy/release/test/` (pipeline task results) AND `policy/release/test_attestation/` (in-toto attestations). These packages must maintain feature parity. |
| Modify attestation trust verification | `policy/lib/intoto/trust.rego` couples intoto, sigstore, tekton, and OCI builtins. Fail-closed: if any step fails, the statement is excluded (no error emitted). Consumer deny rules surface the absence. |

## PR Conventions

Conventional commits are encouraged. Run `make ci` before pushing. CI runs on every PR via
`.github/workflows/pre-merge-ci.yaml`. Policy bundles are published on merge to main via
`.github/workflows/push-bundles.yaml`.

