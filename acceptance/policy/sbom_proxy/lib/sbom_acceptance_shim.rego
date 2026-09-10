package lib.sbom

import rego.v1

# The SBOM proxy scenarios use static policy-input samples captured after CLI
# validation. Those samples do not retain an image reference, so expose their
# embedded SBOMs to the downstream proxy rules exercised by these scenarios.
# This shim is scoped to the sbom_proxy feature; runtime signature verification
# is covered by policy/lib/sbom/sbom_test.rego.
_verified_sbom_attestations contains attestation if {
	some attestation in input.attestations
}
