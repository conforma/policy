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

**Collections** (`policy/*/collection/`) group related rules. Collection files are minimal package
declarations (e.g., `package collection.minimal`) — they do not import policy packages. Rules declare
their own collection membership via a `collections:` list in their METADATA `custom:` annotations
(see `policy/release/attestation_type/attestation_type.rego` for the pattern). Examples: `minimal`
(basic validation), `slsa3` (SLSA Level 3), `redhat` (Red Hat-specific).

**SLSA dual-format:** The library in `policy/lib/tekton/` normalizes both SLSA v0.2 and v1.0
attestation formats. Policies consume the normalized form — don't branch on SLSA version in rules.

**Rule data** lives in `example/data/` (required tasks, trusted task bundles, known RPM repos).
These files have `effective_on` dates — rules with future dates are warnings, not failures.

## Common Change Patterns

- **Add a release policy rule:** follow the pattern in `policy/release/attestation_type/attestation_type.rego` (rule + `_test.rego` in a subdirectory, declare `collections:` in METADATA)
- **Add a pipeline policy rule:** follow the pattern in `policy/pipeline/required_tasks.rego`
- **Add a shared library function:** see `policy/lib/tekton/` for reference implementation (must have test coverage)
- **Fetch and parse an OCI blob:** use `oci.parsed_blob(ref)` from `data.lib.oci`, not `json.unmarshal(ec.oci.blob(ref))` directly. A Regal lint rule (`prefer-parsed-blob`) enforces this
- **Add a new collection:** follow the pattern in `policy/release/collection/` — a minimal package declaration (no imports needed)

## PR Conventions

Conventional commits are encouraged. Run `make ci` before pushing. CI runs on every PR via
`.github/workflows/pre-merge-ci.yaml`. Policy bundles are published on merge to main via
`.github/workflows/push-bundles.yaml`.

