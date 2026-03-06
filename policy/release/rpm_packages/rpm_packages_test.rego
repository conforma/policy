package rpm_packages_test

import rego.v1

import data.lib.assertions
import data.lib.tekton_test
import data.rpm_packages

test_success_cyclonedx if {
	att := _attestation_with_sboms([_cyclonedx_url_1, _cyclonedx_url_1])

	assertions.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_success_spdx if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_1])

	assertions.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_failure_cyclonedx if {
	att := _attestation_with_sboms([_cyclonedx_url_1, _cyclonedx_url_2])

	expected := {{
		"code": "rpm_packages.unique_version",
		"msg": sprintf("%s %s", [
			"Mismatched versions of the \"spam\" RPM were found across different arches.",
			"Platform linux/amd64 has spam-1.0.0-1. Platform linux/arm64 has spam-1.0.0-2.",
		]),
		"term": "spam",
	}}

	assertions.assert_equal_results(expected, rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_failure_spdx if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_2])

	expected := {{
		"code": "rpm_packages.unique_version",
		"msg": sprintf("%s %s", [
			"Mismatched versions of the \"spam\" RPM were found across different arches.",
			"Platform linux/amd64 has spam-1.0.0-1. Platform linux/arm64 has spam-1.0.0-2.",
		]),
		"term": "spam",
	}}

	assertions.assert_equal_results(expected, rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image-index-digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_non_image_index if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_2])

	assertions.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-manifest@sha256:image-manifest-digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_ignore_names if {
	att := _attestation_with_sboms([_spdx_url_1, _spdx_url_2])

	assertions.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image-index-digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
		with data.rule_data.non_unique_rpm_names as ["spam"]
}

test_success_multiple_versions_same_across_platforms if {
	# Both platforms have the same set of multiple spam versions - should NOT trigger violation
	att := _attestation_with_sboms([_multi_spam_url, _multi_spam_url])

	assertions.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_failure_multiple_versions_different_across_platforms if {
	# One platform has multiple spam versions, another has single - should trigger violation
	att := _attestation_with_sboms([_multi_spam_url, _single_spam_url])

	expected := {{
		"code": "rpm_packages.unique_version",
		"msg": sprintf("%s %s", [
			"Mismatched versions of the \"spam\" RPM were found across different arches.",
			"Platform linux/amd64 has spam-1.0.0-1, spam-1.0.0-2. Platform linux/arm64 has spam-1.0.0-1.",
		]),
		"term": "spam",
	}}

	assertions.assert_equal_results(expected, rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

test_failure_with_platform_grouping if {
	# Three platforms have spam-1.0.0-1, one platform has spam-1.0.0-3 - should trigger violation with grouping
	att := _attestation_with_sboms([_single_spam_url, _single_spam_url, _single_spam_url, _spam_v3_url])

	expected := {{
		"code": "rpm_packages.unique_version",
		"msg": sprintf("%s %s", [
			"Mismatched versions of the \"spam\" RPM were found across different arches.",
			"Platform linux/s390x has spam-1.0.0-3. Platforms linux/amd64, linux/arm64, linux/ppc64le have spam-1.0.0-1.",
		]),
		"term": "spam",
	}}

	assertions.assert_equal_results(expected, rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

# Test that lockfile entries (with repository_id but no distro) are filtered out
# This simulates the real-world scenario where SBOMs contain entries for all architectures
# from the rpm lockfile, but only the installed packages should be compared
test_lockfile_entries_filtered if {
	att := _attestation_with_sboms([_sbom_with_lockfile_amd64, _sbom_with_lockfile_arm64])

	# Should NOT trigger violation because installed versions are the same (spam-1.0.0-1)
	# even though lockfile entries show different versions for other arches
	assertions.assert_empty(rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

# Test that actual version mismatch is still detected even with lockfile noise
test_mismatch_detected_with_lockfile_noise if {
	att := _attestation_with_sboms([_sbom_with_lockfile_amd64, _sbom_with_lockfile_arm64_different])

	expected := {{
		"code": "rpm_packages.unique_version",
		"msg": sprintf("%s %s", [
			"Mismatched versions of the \"spam\" RPM were found across different arches.",
			"Platform linux/amd64 has spam-1.0.0-1. Platform linux/arm64 has spam-1.0.0-2.",
		]),
		"term": "spam",
	}}

	assertions.assert_equal_results(expected, rpm_packages.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/image-index@sha256:image_index_digest"
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.index.v1+json"}
		with ec.oci.blob as _mock_blob
}

# CycloneDX mock blobs - purls must have distro= qualifier to be considered installed
_mock_blob(`registry.local/cyclonedx-1@sha256:cyclonedx-1-digest`) := json.marshal({"components": [
	{"purl": "pkg:rpm/redhat/spam@1.0.0-1?distro=rhel-10.0"},
	{"purl": "pkg:rpm/redhat/bacon@1.0.0-2?distro=rhel-10.0"},
	{"purl": "pkg:rpm/redhat/ham@4.2.0-0?distro=rhel-10.0"},
]})

_mock_blob(`registry.local/cyclonedx-2@sha256:cyclonedx-2-digest`) := json.marshal({"components": [
	{"purl": "pkg:rpm/redhat/spam@1.0.0-2?distro=rhel-10.0"},
	{"purl": "pkg:rpm/redhat/bacon@1.0.0-2?distro=rhel-10.0"},
	{"purl": "pkg:rpm/redhat/eggs@4.2.0-0?distro=rhel-10.0"},
]})

# SPDX mock blobs - purls must have distro= qualifier to be considered installed
_mock_blob(`registry.local/spdx-1@sha256:spdx-1-digest`) := json.marshal({"packages": [
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/bacon@1.0.0-2?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		# Intentionally different since we match both PACKAGE_MANAGER and PACKAGE-MANAGER
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/ham@4.2.0-0?distro=rhel-10.0",
	}]},
]})

_mock_blob(`registry.local/spdx-2@sha256:spdx-2-digest`) := json.marshal({"packages": [
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-2?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/bacon@1.0.0-2?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		# Intentionally different since we match both PACKAGE_MANAGER and PACKAGE-MANAGER
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": "pkg:rpm/redhat/eggs@4.2.0-0?distro=rhel-10.0",
	}]},
]})

# Mock blob with multiple versions of spam (both 1.0.0-1 and 1.0.0-2)
_mock_blob(`registry.local/multi-spam@sha256:multi-spam-digest`) := json.marshal({"packages": [
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-2?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/bacon@1.0.0-2?distro=rhel-10.0",
	}]},
]})

# Mock blob with only one version of spam (1.0.0-1) - for mismatch testing
_mock_blob(`registry.local/single-spam@sha256:single-spam-digest`) := json.marshal({"packages": [
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/bacon@1.0.0-2?distro=rhel-10.0",
	}]},
]})

# Mock blob with spam version 1.0.0-3 - for grouping test
_mock_blob(`registry.local/spam-v3@sha256:spam-v3-digest`) := json.marshal({"packages": [
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-3?distro=rhel-10.0",
	}]},
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/bacon@1.0.0-2?distro=rhel-10.0",
	}]},
]})

# Mock blob simulating amd64 SBOM with lockfile entries for all arches
# The installed package (with distro=) is spam-1.0.0-1
# Lockfile entries (with repository_id=) show spam-1.0.0-2 for arm64 - should be ignored
_mock_blob(`registry.local/sbom-lockfile-amd64@sha256:sbom-lockfile-amd64-digest`) := json.marshal({"packages": [
	# Installed package on this platform
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1?arch=x86_64&distro=rhel-10.0",
	}]},
	# Lockfile entry for arm64 - different version, should be filtered out
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-2?arch=aarch64&repository_id=rhel-10-for-aarch64-baseos-rpms",
	}]},
]})

# Mock blob simulating arm64 SBOM with lockfile entries - installed version matches amd64
_mock_blob(`registry.local/sbom-lockfile-arm64@sha256:sbom-lockfile-arm64-digest`) := json.marshal({"packages": [
	# Installed package on this platform - same version as amd64
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1?arch=aarch64&distro=rhel-10.0",
	}]},
	# Lockfile entry for amd64 - should be filtered out
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1?arch=x86_64&repository_id=rhel-10-for-x86_64-baseos-rpms",
	}]},
]})

# Mock blob simulating arm64 SBOM with different installed version than amd64
# regal ignore:line-length
_mock_blob(`registry.local/sbom-lockfile-arm64-diff@sha256:sbom-lockfile-arm64-diff-digest`) := json.marshal({"packages": [
	# Installed package on this platform - DIFFERENT version than amd64
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-2?arch=aarch64&distro=rhel-10.0",
	}]},
	# Lockfile entry for amd64 - should be filtered out
	{"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": "pkg:rpm/redhat/spam@1.0.0-1?arch=x86_64&repository_id=rhel-10-for-x86_64-baseos-rpms",
	}]},
]})

_sbom_with_lockfile_amd64 := "registry.local/sbom-lockfile-amd64@sha256:sbom-lockfile-amd64-digest"

_sbom_with_lockfile_arm64 := "registry.local/sbom-lockfile-arm64@sha256:sbom-lockfile-arm64-digest"

_sbom_with_lockfile_arm64_different := "registry.local/sbom-lockfile-arm64-diff@sha256:sbom-lockfile-arm64-diff-digest"

_cyclonedx_url_1 := "registry.local/cyclonedx-1@sha256:cyclonedx-1-digest"

_cyclonedx_url_2 := "registry.local/cyclonedx-2@sha256:cyclonedx-2-digest"

_spdx_url_1 := "registry.local/spdx-1@sha256:spdx-1-digest"

_spdx_url_2 := "registry.local/spdx-2@sha256:spdx-2-digest"

_multi_spam_url := "registry.local/multi-spam@sha256:multi-spam-digest"

_single_spam_url := "registry.local/single-spam@sha256:single-spam-digest"

_spam_v3_url := "registry.local/spam-v3@sha256:spam-v3-digest"

_attestation_with_sboms(sbom_urls) := attestation if {
	platforms := ["linux/amd64", "linux/arm64", "linux/ppc64le", "linux/s390x"]
	tasks := [task |
		some i, url in sbom_urls
		platform := platforms[i % count(platforms)]
		_task := tekton_test.resolved_slsav1_task(
			sprintf("some-build-%d", [i]),
			[{
				"name": "PLATFORM",
				"value": platform,
			}],
			[
				{
					"name": "SBOM_BLOB_URL",
					"value": url,
				},
				{
					"name": "IMAGES",
					"value": "registry.local/image@sha256:abc",
				},
			],
		)
		task := tekton_test.with_bundle(_task, _bundle)
	]

	attestation := tekton_test.slsav1_attestation(tasks)
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
