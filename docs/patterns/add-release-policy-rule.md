# Pattern: Add a Release Policy Rule

Reference implementation: `policy/release/attestation_type.rego`

## Steps

1. Create `policy/release/<rule_name>.rego` with METADATA annotations
2. Create `policy/release/<rule_name>_test.rego` with full test coverage
3. Add the rule's package import to the appropriate collection(s) in `policy/release/collection/`
4. Run `make test` to verify coverage, `make fmt` to format, `make generate-docs` to update docs
