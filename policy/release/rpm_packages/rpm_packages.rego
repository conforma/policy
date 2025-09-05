#
# METADATA
# title: RPM Packages
# description: >-
#   Rules used to verify different properties of specific RPM packages found in the SBOM of the
#   image being validated.
#
package rpm_packages

import rego.v1

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
#   # Pushed back again due to https://issues.redhat.com/browse/EC-1354
#   effective_on: 2025-10-01T00:00:00Z
#
deny contains result if {
	image.is_image_index(input.image.ref)

	some name in rpm_names_with_mismatched_nvr_sets
	not name in lib.rule_data("non_unique_rpm_names")

	rpm_mismatch_details := [detail |
		some platform, nvrs in all_rpms_by_name_and_platform[name]
		detail := sprintf("Platform %s has %s.", [platform, concat(", ", sort(nvrs))])
	]
	detail_text := concat(" ", sort(rpm_mismatch_details))

	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[name, detail_text],
		name,
	)
}

# Detect RPMs where the set of nvrs differs across platforms.
# Generally the sets of versions are of size one, but in some cases we have more
# than one version of a particular rpm due to multi-stage builds.
rpm_names_with_mismatched_nvr_sets contains rpm_name if {
	some rpm_name, platforms in all_rpms_by_name_and_platform
	nvr_sets := {nvrs | some _platform, nvrs in platforms}

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
	rpm_name := rpm.name
	rpm_version := rpm.version

	# We really only need the version, but it's convenient for
	# creating violation messages if we use the full nvr here.
	# Note that rpm.version is actually the version and the release in
	# RPM terms, hence this is the name-version-release, aka the nvr
	nvr := sprintf("%s-%s", [rpm_name, rpm_version])
}
