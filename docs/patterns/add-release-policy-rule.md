# Pattern: Add a Release Policy Rule

Reference implementation: `policy/release/attestation_type/attestation_type.rego`

## Steps

1. Create `policy/release/<rule_name>/<rule_name>.rego` with METADATA annotations (including `collections:` list under `custom:`)
2. Create `policy/release/<rule_name>/<rule_name>_test.rego` with full test coverage
3. Run `make test` to verify coverage, `make fmt` to format, `make generate-docs` to update docs
