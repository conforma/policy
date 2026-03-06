#
# METADATA
# title: SBOM
# description: >-
#   Checks general properties of the SBOMs associated with the image being validated. More specific
#   rules for SPDX and CycloneDX SBOMs are in separate packages.
#
package sbom

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.konflux

# METADATA
# title: Found
# description: Confirm an SBOM attestation exists.
# custom:
#   short_name: found
#   failure_msg: No SBOM attestations found
#   solution: >-
#     Make sure the build process produces an SBOM attestation.
#   collections:
#   - minimal
#   - redhat
deny contains result if {
	# TODO: Workaround until Konflux produces SBOMs for Image Indexes:
	# https://issues.redhat.com/browse/KONFLUX-4330
	not konflux.is_validating_image_index

	count(_sboms) == 0
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Disallowed packages list is provided
# description: >-
#   Confirm the `disallowed_packages` and `disallowed_attributes` rule data were
#   provided, since they are required by the policy rules in this package.
# custom:
#   short_name: disallowed_packages_provided
#   failure_msg: "%s"
#   solution: >-
#     Provide a list of disallowed packages or package attributes in the
#     expected format.
#   collections:
#   - redhat
#   - policy_data
#   - redhat_rpms
deny contains result if {
	some error in lib.sbom.rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
}

_sboms := array.concat(lib.sbom.spdx_sboms, lib.sbom.cyclonedx_sboms)
