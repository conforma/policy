# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repository contains Rego policies for the Enterprise Contract (EC) and Konflux. It validates container image attestations, pipeline definitions, and Tekton tasks using the Open Policy Agent (OPA) framework. Policies are bundled as OCI artifacts and pushed to quay.io for consumption by the EC CLI tool.

## Essential Commands

### Testing
```bash
make test                    # Run all tests in verbose mode with coverage check
make quiet-test              # Run all tests in quiet mode with coverage
make TEST=<pattern> test     # Run specific tests matching regex pattern
make coverage                # Show uncovered lines of rego code
make watch                   # Run tests in watch mode
make live-test               # Continuously run tests on file changes (requires entr)
```

Run a single test with the ec CLI:
```bash
ec opa test ./policy -r <test_name_matcher>
# or
go run github.com/conforma/cli opa test ./policy -r <test_name_matcher>
```

### CI & Quality
```bash
make ci                      # Run all checks: tests, formatting, linting, docs generation
make fmt                     # Format all rego files (run before committing)
make fmt-check               # Check if rego files are properly formatted
make lint                    # Run regal linter and license header checks
make opa-check               # Check rego files with OPA strict mode
make conventions-check       # Check policy files for convention violations
```

### Documentation
```bash
make generate-docs           # Regenerate policy documentation (commit all modified files)
```

### Acceptance Testing
```bash
cd acceptance && go test ./...   # Run acceptance tests
```

### Policy Bundles
```bash
make update-bundles          # Push policy bundles to quay.io and generate infra-deployments PRs
```

### Testing Against Real Data
```bash
# Fetch and test against real attestations
make fetch-att                              # Fetch default image attestation
make fetch-att IMAGE=<ref> KEY=<keyfile>   # Fetch specific image
make dummy-config                           # Create dummy policy config
make check-release                          # Verify build using policies

# Fetch and test against pipeline definitions
make fetch-pipeline                         # Fetch default pipeline
make fetch-pipeline PIPELINE=<name>        # Fetch specific pipeline
make check-pipeline                         # Verify pipeline using policies
```

## Architecture

### Policy Organization

The repository is structured around three main policy domains:

1. **Release Policies** ([policy/release/](policy/release/))
   - Validate container image build attestations (SLSA provenance)
   - Organized into focused policy packages (e.g., `attestation_type`, `cve`, `slsa_provenance_available`)
   - Policy collections group related rules (e.g., `minimal`, `github`, `redhat`, `slsa3`)
   - Collections are defined in [policy/release/collection/](policy/release/collection/)

2. **Pipeline Policies** ([policy/pipeline/](policy/pipeline/))
   - Validate Tekton pipeline definitions
   - Ensure pipelines meet security and compliance requirements

3. **Task Policies** ([policy/task/](policy/task/))
   - Validate individual Tekton task definitions
   - Check task annotations, images, and trusted artifact usage

4. **Build Task Policies** ([policy/build_task/](policy/build_task/))
   - Validate build task configurations (e.g., build labels)

5. **StepAction Policies** ([policy/stepaction/](policy/stepaction/))
   - Validate Tekton StepAction definitions

### Shared Libraries

[policy/lib/](policy/lib/) contains reusable helper functions:
- `tekton/` - Parse and extract data from SLSA v0.2 and v1.0 attestations
- `image/` - Image reference parsing and validation
- `sbom/` - SBOM parsing (CycloneDX, SPDX) and RPM package analysis
- `arrays/`, `time/`, `json/` - General utilities
- `k8s/` - Kubernetes resource helpers
- `konflux/` - Konflux-specific helpers

The Tekton library handles both SLSA v0.2 and v1.0 attestation formats, normalizing task data from different schema versions.

### Policy Collections

Collections are groups of related policy rules. Each collection imports specific policy packages. For example, `collection.minimal` includes basic build pipeline validation, while `collection.slsa3` includes comprehensive SLSA Level 3 requirements.

### Data Files

[example/data/](example/data/) contains policy configuration data:
- `rule_data.yml` - Rule-specific configuration
- `required_tasks.yml` - Required Tekton tasks with effective dates
- `trusted_tekton_tasks.yml` - Trusted task bundle references
- `known_rpm_repositories.yml` - Allowed RPM repositories

### Testing Requirements

- All policy files must have corresponding `_test.rego` files
- 100% test coverage is enforced by CI
- Tests use standard OPA testing framework
- The `checks/` directory contains convention validators run during CI

### Tools & Dependencies

- **EC CLI** (github.com/conforma/cli) - Used for `opa` and `conftest` commands with custom rego functions
- Go version specified in [go.mod](go.mod) (using exact pinned versions via `go run`)
- Tests run in network-isolated environment when `unshare` is available
- All tools are executed via `go run` to use exact pinned versions from go.mod

### Policy Annotations

All policy rules must include METADATA annotations:
- `title` - Short rule name
- `description` - What the rule validates
- `custom.short_name` - Machine-readable identifier
- `custom.failure_msg` - User-facing error message

These conventions are enforced by `make conventions-check`.

### Documentation Generation

Policy documentation is auto-generated from rego annotations using a custom Go tool in [docs/](docs/). The generated Antora documentation is published to conforma.dev.

### CI/CD

- [.github/workflows/pre-merge-ci.yaml](.github/workflows/pre-merge-ci.yaml) - Runs all tests and checks
- [.github/workflows/push-bundles.yaml](.github/workflows/push-bundles.yaml) - Publishes policy bundles as OCI artifacts on main branch pushes
- [.github/workflows/docs.yaml](.github/workflows/docs.yaml) - Publishes documentation

## Development Workflow

1. Make changes to policy rego files
2. Run `make fmt` to format code
3. Ensure tests pass with 100% coverage: `make test`
4. If adding/modifying policy rules, run `make generate-docs` and commit the changes
5. Run `make ci` to verify all checks pass before pushing
