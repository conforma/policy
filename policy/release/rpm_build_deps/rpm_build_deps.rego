#
# METADATA
# title: RPM Build Dependencies
# description: >-
#   Checks different properties of the CycloneDX SBOMs associated with the image being validated.
#
package rpm_build_deps

import rego.v1

import data.lib
import data.lib.sbom

# METADATA
# title: Builds have valid download locations
# description: Builds have valid download locations for RPM build dependencies
# custom:
#   short_name: download_location_valid
#   failure_msg: RPM build dependency source %s is not in the allowed list %v.
#   collections:
#   - redhat_rpms
warn contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages

	# NOASSERTION is displayed in the SBOM for the RPMS that have been built
	valid_locations := array.concat(["NOASSERTION"], lib.rule_data("allowed_rpm_build_dependency_sources"))
	not matches_any(pkg.downloadLocation, valid_locations)
	result := lib.result_helper(rego.metadata.chain(), [pkg.downloadLocation, valid_locations])
}

matches_any(branch, valid_locations) if {
	#	some pattern in lib.rule_data("allowed_target_branch_patterns")
	some pattern in valid_locations
	regex.match(pattern, branch)
}
