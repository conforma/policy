#
# METADATA
# title: RPM Packages
# description: >-
#   Rules used to verify different properties of specific RPM packages found in the SBOM of the
#   image being validated.
#
package rpm_packages

import rego.v1

import data.lib.utils
import data.lib
import data.lib.image
import data.lib.sbom
import data.lib.tekton

# METADATA
# title: Unique Version
# description: >-
#   Check if a multi-arch build has the same RPM versions installed across each different
#   architecture. This check only applies for Image Indexes, aka multi-platform images.
#   Use the `non_unique_rpm_names` rule data key to ignore certain RPMs.
# custom:
#   short_name: unique_version
#   failure_msg: 'Mismatched versions of the %q RPM were found across different arches. %s'
#   collections:
#   - redhat
#
deny contains result if {
	image.is_image_index(input.image.ref)

	some rpm_name in rpm_names_with_mismatched_nvr_sets
	not rpm_name in utils.rule_data("non_unique_rpm_names")

	detail_text := concat(" ", sort(rpm_mismatch_details(rpm_name)))

	result := utils.result_helper_with_term(
		rego.metadata.chain(),
		[rpm_name, detail_text],
		rpm_name,
	)
}

# Do some extra work here to make a nice tidy violation message
rpm_mismatch_details(rpm_name) := [detail |
	# Get all unique NVR sets for this RPM
	some nvr_set in {nvrs |
		some platform, nvrs in all_rpms_by_name_and_platform[rpm_name]
	}

	# Find all platforms that have this NVR set
	platforms_with_nvr_set := [platform |
		some platform, nvrs in all_rpms_by_name_and_platform[rpm_name]
		nvrs == nvr_set
	]

	detail := sprintf("%s %s %s %s.", [
		utils.pluralize_maybe(platforms_with_nvr_set, "Platform", ""),
		concat(", ", sort(platforms_with_nvr_set)),
		utils.pluralize_maybe(platforms_with_nvr_set, "has", "have"),
		concat(", ", sort(nvr_set)),
	])
]

# Detect RPMs where the set of nvrs differs across platforms.
# Generally the sets of versions are of size one, but in some cases we have more
# than one version of a particular rpm due to multi-stage builds.
rpm_names_with_mismatched_nvr_sets contains rpm_name if {
	some rpm_name, platform_sets in all_rpms_by_name_and_platform
	nvr_sets := {nvrs | some _platform, nvrs in platform_sets}

	# If there are more than one unique set of nvrs, then we have some
	# kind of mismatch between the platforms
	count(nvr_sets) > 1
}

# A list of rpms grouped by rpm name and by platform
# Something like this:
# {
#   "acl": {
#     "linux/arm64": ["acl-2.3.1-4.el9"],
#     "linux/ppc64le": ["acl-2.3.1-4.el9"],
#     ...
#   },
#   ...
# }
all_rpms_by_name_and_platform[rpm_name][platform] contains nvr if {
	some attestation in lib.pipelinerun_attestations

	# We're expecting multiple matrixed build tasks, one
	# for each platform
	some build_task in tekton.build_tasks(attestation)

	# Determine which os/arch was built by this build task.
	# Note: We expect this to be present for the Konflux multi-arch builds. If it
	# isn't then this check doesn't work and mismatched rpm versions will not be
	# detected. If there was somehow a different way to build a multi-arch image,
	# we would need to find another way to figure out which platform each SBOM is
	# related to.
	platform := tekton.task_param(build_task, "PLATFORM")

	# Find the SBOM location
	some result in tekton.task_results(build_task)
	result.name == "SBOM_BLOB_URL"
	sbom_blob_ref := result.value

	# Fetch the SBOM data
	sbom_blob := ec.oci.blob(sbom_blob_ref)
	s := json.unmarshal(sbom_blob)

	# Extract the list of rpm purls from the SBOM and parse out
	# the rpm version details
	some rpm_info in sbom.rpms_from_sbom(s)
	rpm := ec.purl.parse(rpm_info.purl)

	# Filter to only include RPMs that are actually installed on this platform.
	# Installed RPMs have a "distro" qualifier (e.g., distro=rhel-10.1), while
	# lockfile entries for other architectures have "repository_id" instead.
	# Without this filter, all platforms appear to have the same RPMs because
	# the SBOM includes lockfile entries for all architectures.
	_is_installed_rpm(rpm)

	rpm_name := rpm.name
	rpm_version := rpm.version

	# We really only need the version, but it's convenient for
	# creating violation messages if we use the full nvr here.
	# Note that rpm.version is actually the version and the release in
	# RPM terms, hence this is the name-version-release, aka the nvr
	nvr := sprintf("%s-%s", [rpm_name, rpm_version])
}

# Check if an RPM purl represents an installed package (has "distro" qualifier)
# vs a lockfile entry (has "repository_id" qualifier instead)
_is_installed_rpm(rpm) if {
	some qualifier in rpm.qualifiers
	qualifier.key == "distro"
}
