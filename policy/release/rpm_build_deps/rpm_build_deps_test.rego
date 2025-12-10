#
# METADATA
# title: RPM Build Dependencies tests
# description: >-
#   Tests for rpm_build_deps policy
#
package rpm_build_deps_test

import rego.v1

import data.lib
import data.rpm_build_deps

# Test with valid download location - NOASSERTION (always allowed)
test_valid_download_location_noassertion if {
	att := _sbom_attestation_with_download_location("NOASSERTION")
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with valid download location - brewroot pattern
test_valid_download_location_brewroot if {
	att := _sbom_attestation_with_download_location("https://download.devel.redhat.com/brewroot/repos/some-package.rpm")
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with valid download location - codeload pattern
test_valid_download_location_codeload if {
	att := _sbom_attestation_with_download_location("https://codeload.github.com/user/repo/tar.gz/v1.0.0")
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with valid download location - pypi pattern
test_valid_download_location_pypi if {
	att := _sbom_attestation_with_download_location("https://files.pythonhosted.org/packages/some-package-1.0.tar.gz")
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with valid download location - maven central pattern
test_valid_download_location_maven if {
	location := "https://repo.maven.apache.org/maven2/org/example/artifact/1.0/artifact-1.0.jar"
	att := _sbom_attestation_with_download_location(location)
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with invalid download location - doesn't match any allowed pattern
test_invalid_download_location if {
	invalid_location := "https://untrusted.example.com/package.rpm"
	att := _sbom_attestation_with_download_location(invalid_location)
	expected_locations := array.concat(["NOASSERTION"], _mock_allowed_locations)
	expected := {{
		"code": "rpm_build_deps.download_location_valid",
		"msg": sprintf(
			"RPM build dependency source %s is not in the allowed list %v.",
			[invalid_location, expected_locations],
		),
	}}
	lib.assert_equal_results(expected, rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with multiple packages - all valid
test_multiple_packages_all_valid if {
	att := _sbom_attestation_with_multiple_packages([
		"NOASSERTION",
		"https://download.devel.redhat.com/brewroot/repos/package1.rpm",
		"https://codeload.github.com/org/repo/tar.gz/v2.0",
	])
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with multiple packages - one invalid
test_multiple_packages_one_invalid if {
	att := _sbom_attestation_with_multiple_packages([
		"NOASSERTION",
		"https://untrusted.example.com/package.rpm",
		"https://download.devel.redhat.com/brewroot/repos/package2.rpm",
	])
	results := rpm_build_deps.warn with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
	count(results) == 1
}

# Test with multiple packages - all invalid
test_multiple_packages_all_invalid if {
	att := _sbom_attestation_with_multiple_packages([
		"https://untrusted1.example.com/package1.rpm",
		"https://untrusted2.example.com/package2.rpm",
	])
	results := rpm_build_deps.warn with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
	count(results) == 2
}

# Test with empty SBOM
test_empty_sbom if {
	att := {"statement": {
		"predicateType": "https://spdx.dev/Document",
		"predicate": {
			"spdxVersion": "SPDX-2.3",
			"packages": [],
		},
	}}
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as _mock_allowed_locations
}

# Test with empty rule_data - should only allow NOASSERTION
test_empty_rule_data_warns_urls if {
	att := _sbom_attestation_with_download_location("https://download.devel.redhat.com/brewroot/repos/package.rpm")
	results := rpm_build_deps.warn with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as []
	count(results) == 1
}

# Test NOASSERTION is always allowed even with empty rule_data
test_noassertion_allowed_with_empty_rule_data if {
	att := _sbom_attestation_with_download_location("NOASSERTION")
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as []
}

# Test with custom rule_data
test_custom_rule_data if {
	custom_locations := ["^https://custom\\.example\\.com/.*", "^https://archive\\.example\\.org/.*"]
	att := _sbom_attestation_with_download_location("https://custom.example.com/packages/foo.rpm")
	lib.assert_empty(rpm_build_deps.warn) with input.attestations as [att]
		with data.rule_data.allowed_rpm_build_dependency_sources as custom_locations
}

# Test matches_any function - valid with exact match
test_matches_any_exact_match if {
	rpm_build_deps.matches_any("NOASSERTION", ["NOASSERTION"])
}

# Test matches_any function - valid with regex pattern
test_matches_any_regex_pattern if {
	rpm_build_deps.matches_any(
		"https://download.devel.redhat.com/brewroot/repos/package.rpm",
		["^https://download\\.devel\\.redhat\\.com/brewroot/repos/.*"],
	)
}

# Test matches_any function - invalid
test_matches_any_invalid if {
	not rpm_build_deps.matches_any("https://untrusted.example.com/package.rpm", _mock_allowed_locations)
}

# Test matches_any with multiple patterns
test_matches_any_multiple_patterns if {
	patterns := [
		"^https://download\\.devel\\.redhat\\.com/.*",
		"^https://codeload\\.github\\.com/.*",
	]
	rpm_build_deps.matches_any("https://codeload.github.com/user/repo/tar.gz/v1.0", patterns)
}

# Helper function to create SBOM attestation with specific download location
_sbom_attestation_with_download_location(location) := {"statement": {
	"predicateType": "https://spdx.dev/Document",
	"predicate": {
		"spdxVersion": "SPDX-2.3",
		"documentNamespace": "https://example.dev/spdxdocs/example-123",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-sbom",
		"creationInfo": {
			"created": "2024-01-01T00:00:00Z",
			"creators": ["Tool: test"],
		},
		"packages": [{
			"SPDXID": "SPDXRef-Package-test",
			"name": "test-package",
			"versionInfo": "1.0.0",
			"downloadLocation": location,
		}],
	},
}}

# Helper function to create SBOM attestation with multiple packages
_sbom_attestation_with_multiple_packages(locations) := {"statement": {
	"predicateType": "https://spdx.dev/Document",
	"predicate": {
		"spdxVersion": "SPDX-2.3",
		"documentNamespace": "https://example.dev/spdxdocs/example-456",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test-sbom-multi",
		"creationInfo": {
			"created": "2024-01-01T00:00:00Z",
			"creators": ["Tool: test"],
		},
		"packages": [pkg |
			some i, location in locations
			pkg := {
				"SPDXID": sprintf("SPDXRef-Package-%d", [i]),
				"name": sprintf("package-%d", [i]),
				"versionInfo": "1.0.0",
				"downloadLocation": location,
			}
		],
	},
}}

# Mock rule data - allowed source locations for testing
# These patterns represent common trusted sources for RPM build dependencies
_mock_allowed_locations := [
	"^https://download\\.devel\\.redhat\\.com/brewroot/repos/.*",
	"^https://codeload\\.github\\.com/.*",
	"^https://files\\.pythonhosted\\.org/.*",
	"^https://repo\\.maven\\.apache\\.org/maven2/.*",
]
