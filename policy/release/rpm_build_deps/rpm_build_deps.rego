#
# METADATA
# title: RPM Build Dependencies
# description: >-
#   Checks different properties of the CycloneDX SBOMs associated with the image being validated.
#
package rpm_build_deps

import rego.v1

import data.lib.metadata
import data.lib.rule_data
import data.lib.sbom

# METADATA
# title: Builds have valid download locations
# description: Builds have valid download locations for RPM build dependencies
# custom:
#   short_name: download_location_valid
#   failure_msg: RPM build dependency source %s is not in the allowed list %v.
#   collections:
#   - redhat_rpms
#   - redhat_security
warn contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages

	# NOASSERTION is displayed in the SBOM for the RPMS that have been built
	valid_locations := array.concat(["NOASSERTION"], rule_data.get("allowed_rpm_build_dependency_sources"))
	not matches_any(pkg.downloadLocation, valid_locations)
	result := metadata.result_helper(rego.metadata.chain(), [pkg.downloadLocation, valid_locations])
}

matches_any(branch, valid_locations) if {
	#	some pattern in rule_data.get("allowed_target_branch_patterns")
	some pattern in valid_locations
	regex.match(pattern, branch)
}

# METADATA
# title: allowed_rpm_build_dependency_sources format
# description: >-
#   Confirm the `allowed_rpm_build_dependency_sources` rule data uses anchored regex patterns.
# custom:
#   short_name: allowed_rpm_build_dependency_sources_format
#   failure_msg: "%s"
#   collections:
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
}

_rule_data_errors contains error if {
	some error in rule_data.anchoring_errors("allowed_rpm_build_dependency_sources")
}
