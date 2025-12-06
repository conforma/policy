# AGENTS.md

This file provides guidance to AI coding agents when working with code in this repository.

## Project Overview

This repository contains Rego policies for the Enterprise Contract (EC) and Konflux. It validates container image attestations, pipeline definitions, and Tekton tasks using the Open Policy Agent (OPA) framework. Policies are bundled as OCI artifacts and pushed to quay.io for consumption by the EC CLI tool.

## Setup Commands

```bash
# Install dependencies (Go modules will auto-download)
go mod download

# Verify installation
make ci
```

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

## Code Style & Conventions

### Rego Policy Structure

- All policy files must have corresponding `_test.rego` files
- 100% test coverage is enforced by CI
- Use standard OPA testing framework

### Policy Annotations

All policy rules must include METADATA annotations:
```rego
# METADATA
# title: Short rule name
# description: What the rule validates
# custom:
#   short_name: machine_readable_identifier
#   failure_msg: User-facing error message
```

### File Organization

1. **Release Policies** - `policy/release/`
   - Validate container image build attestations (SLSA provenance)
   - Organized into focused policy packages (e.g., `attestation_type`, `cve`, `slsa_provenance_available`)
   - Policy collections group related rules in `policy/release/collection/`

2. **Pipeline Policies** - `policy/pipeline/`
   - Validate Tekton pipeline definitions
   - Ensure pipelines meet security and compliance requirements

3. **Task Policies** - `policy/task/`
   - Validate individual Tekton task definitions
   - Check task annotations, images, and trusted artifact usage

4. **Build Task Policies** - `policy/build_task/`
   - Validate build task configurations (e.g., build labels)

5. **StepAction Policies** - `policy/stepaction/`
   - Validate Tekton StepAction definitions

6. **Shared Libraries** - `policy/lib/`
   - `tekton/` - Parse and extract data from SLSA v0.2 and v1.0 attestations
   - `image/` - Image reference parsing and validation
   - `sbom/` - SBOM parsing (CycloneDX, SPDX) and RPM package analysis
   - `arrays/`, `time/`, `json/` - General utilities
   - `k8s/` - Kubernetes resource helpers
   - `konflux/` - Konflux-specific helpers

### Naming Conventions

- Test files must end with `_test.rego`
- Policy packages use snake_case
- Collections are defined in `collection/` directories
- Shared library functions should be reusable and well-documented

## Testing Instructions

### Test Coverage Requirements

- 100% test coverage is mandatory
- All tests must pass before merging
- Tests run in network-isolated environment when `unshare` is available

### Running Tests

```bash
# Run all tests
make test

# Run specific tests
make TEST="pattern" test

# Run in watch mode during development
make live-test

# Check coverage
make coverage
```

### Writing Tests

Use standard OPA testing framework:
```rego
package my_policy_test

import rego.v1
import data.my_policy

test_valid_input if {
    my_policy.deny with input as {"valid": "data"}
}
```

## Development Workflow

1. Make changes to policy rego files
2. Run `make fmt` to format code
3. Ensure tests pass with 100% coverage: `make test`
4. If adding/modifying policy rules, run `make generate-docs` and commit the changes
5. Run `make ci` to verify all checks pass before pushing

## Architecture Details

### Policy Collections

Collections are groups of related policy rules. Each collection imports specific policy packages. For example:
- `collection.minimal` - Basic build pipeline validation
- `collection.slsa3` - Comprehensive SLSA Level 3 requirements
- `collection.github` - GitHub-specific validations
- `collection.redhat` - Red Hat-specific requirements

### Data Files

Configuration data is located in `example/data/`:
- `rule_data.yml` - Rule-specific configuration
- `required_tasks.yml` - Required Tekton tasks with effective dates
- `trusted_tekton_tasks.yml` - Trusted task bundle references
- `known_rpm_repositories.yml` - Allowed RPM repositories

### Tools & Dependencies

- **EC CLI** (`github.com/conforma/cli`) - Used for `opa` and `conftest` commands with custom rego functions
- Go version specified in `go.mod` (using exact pinned versions via `go run`)
- All tools are executed via `go run` to use exact pinned versions from go.mod

### Tekton Attestation Handling

The Tekton library in `policy/lib/tekton/` handles both SLSA v0.2 and v1.0 attestation formats, normalizing task data from different schema versions. This ensures policies work with attestations from different Tekton versions.

## Security Considerations

- Avoid introducing security vulnerabilities (command injection, XSS, SQL injection, OWASP top 10)
- Validate external inputs at system boundaries
- Review attestations and pipeline definitions for security issues
- Trusted task bundles are explicitly configured in `trusted_tekton_tasks.yml`

## CI/CD Pipeline

- `.github/workflows/pre-merge-ci.yaml` - Runs all tests and checks
- `.github/workflows/push-bundles.yaml` - Publishes policy bundles as OCI artifacts on main branch pushes
- `.github/workflows/docs.yaml` - Publishes documentation

## Documentation Generation

Policy documentation is auto-generated from rego annotations using a custom Go tool in `docs/`. The generated Antora documentation is published to conforma.dev.

Run `make generate-docs` after modifying policy annotations and commit all changed files.

## Troubleshooting

### Common Issues

1. **Tests failing with network errors**: Tests run in isolated environment when `unshare` is available
2. **Coverage not at 100%**: Run `make coverage` to identify untested lines
3. **Formatting errors**: Always run `make fmt` before committing
4. **Convention violations**: Run `make conventions-check` to validate policy conventions

### Debugging

```bash
# Run specific test in verbose mode
make TEST="specific_pattern" test

# Check what's not covered
make coverage

# Validate conventions
make conventions-check
```
