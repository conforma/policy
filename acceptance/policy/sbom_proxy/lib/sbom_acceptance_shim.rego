package lib.sbom

import rego.v1

# ACCEPTANCE-ONLY: This file lives under acceptance/policy/sbom_proxy/ and is
# loaded only by the sbom_proxy acceptance harness (see acceptance/features/).
# Production `ec eval` invocations load ./policy (the POLICY_DIR in the
# Makefile), which does not include acceptance/policy/**, so this shim cannot
# extend the production lib.sbom package on the runtime data path. The package
# name is intentionally identical to production so the harness can override
# rules under test; see AGENTS.md ("Acceptance shims must not extend production
# packages") for the guardrail.
#
# The SBOM proxy scenarios use static policy-input samples captured after CLI
# validation. Those samples do not retain an image reference, so expose their
# embedded SBOMs to the downstream proxy rules exercised by these scenarios.
# This shim is scoped to the sbom_proxy feature; runtime signature verification
# is covered by policy/lib/sbom/sbom_test.rego.
_verified_sbom_attestations contains attestation if {
	some attestation in input.attestations
}
