package lib.sbom_test

import rego.v1

import data.lib
import data.lib.assertions
import data.lib.sbom

test_all_sboms if {
	expected := ["hurricane", "tornado", "spandex", "latex"]
	assertions.assert_equal(sbom.all_sboms, expected) with sbom.cyclonedx_sboms as ["hurricane", "tornado"]
		with sbom.spdx_sboms as ["spandex", "latex"]
}

# test from attestation and fallback to oci image
test_cyclonedx_sboms if {
	attestations := [
		{"statement": {
			"predicateType": "https://cyclonedx.org/bom",
			"predicate": "sbom from attestation",
		}},
		{"statement": {
			"predicateType": "https://example.org/boom",
			"predicate": "not an sbom",
		}},
		{"statement": {
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": {
				"buildType": lib.tekton_pipeline_run,
				"buildConfig": {"tasks": [{"results": [
					{
						"name": "IMAGE_DIGEST",
						"type": "string",
						"value": "sha256:284e3029000000000000000000000000000000000000000000000000284e3029",
					},
					{
						"name": "IMAGE_URL",
						"type": "string",
						"value": "registry.io/repository/image:latest",
					},
					{
						"name": "SBOM_BLOB_URL",
						"type": "string",
						"value": "registry.io/repository/image@sha256:f0cacc1a",
					},
				]}]},
			},
		}},
	]
	expected := ["sbom from attestation", {"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	assertions.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as _cyclonedx_image
		with ec.sigstore.verify_attestation as _mock_verify_cyclonedx_attestation
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# test from attestation and fallback to oci image
test_spdx_sboms if {
	attestations := [
		{"statement": {
			"predicateType": "https://spdx.dev/Document",
			"predicate": "sbom from attestation",
		}},
		{"statement": {
			"predicateType": "https://example.org/boom",
			"predicate": "not an sbom",
		}},
		{"statement": {
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": {
				"buildType": lib.tekton_pipeline_run,
				"buildConfig": {"tasks": [{"results": [
					{
						"name": "IMAGE_DIGEST",
						"type": "string",
						"value": "sha256:284e3029000000000000000000000000000000000000000000000000284e3029",
					},
					{
						"name": "IMAGE_URL",
						"type": "string",
						"value": "registry.io/repository/image:latest",
					},
					{
						"name": "SBOM_BLOB_URL",
						"type": "string",
						"value": "registry.io/repository/image@sha256:f0cacc1a",
					},
				]}]},
			},
		}},
	]
	expected := ["sbom from attestation", {"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}]
	assertions.assert_equal(sbom.spdx_sboms, expected) with input.attestations as attestations
		with input.image as _spdx_image
		with ec.sigstore.verify_attestation as _mock_verify_spdx_attestation
		with ec.oci.blob as mock_ec_oci_spdx_blob
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

test_ignore_unrelated_sboms if {
	attestations := [
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:0000000",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1a",
				},
			]}]},
		}}},
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:1111111",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1b",
				},
			]}]},
		}}},
	]

	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as attestations
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029000000000000000000000000000000000000000000000000284e3029"} # regal ignore:line-length
		with ec.oci.blob as ""
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
}

test_image_ref_from_purl if {
	# regal ignore:line-length
	purl := "pkg:oci/ubi-minimal@sha256:92b1d5747a93608b6adb64dfd54515c3c5a360802db4706765ff3d8470df6290?repository_url=registry.access.redhat.com/ubi9/ubi-minimal"

	# regal ignore:line-length
	image_ref := "registry.access.redhat.com/ubi9/ubi-minimal@sha256:92b1d5747a93608b6adb64dfd54515c3c5a360802db4706765ff3d8470df6290"
	assertions.assert_equal(sbom.image_ref_from_purl(purl), image_ref)
}

mock_ec_oci_cyclonedx_blob := `{"sbom": "from oci blob", "bomFormat": "CycloneDX"}`

mock_ec_oci_spdx_blob := `{"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}`

_cyclonedx_image := {
	"ref": "registry.io/repository/image@sha256:284e3029000000000000000000000000000000000000000000000000284e3029",
	"config": {"Labels": {"vendor": "Red Hat, Inc."}},
}

_spdx_image := {
	"ref": "registry.io/repository/image@sha256:284e3029000000000000000000000000000000000000000000000000284e3029",
	"config": {"Labels": {"vendor": "Red Hat, Inc."}},
}

# Test CycloneDX SBOM discovery via OCI Referrers API
test_cyclonedx_sboms_from_referrers if {
	mock_referrers := [
		{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"size": 100,
			# regal ignore:line-length
			"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
			"artifactType": "application/vnd.cyclonedx+json",
			# regal ignore:line-length
			"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		},
		{
			"mediaType": "application/vnd.oci.image.manifest.v1+json",
			"size": 200,
			# regal ignore:line-length
			"digest": "sha256:e5f6a7b800000000000000000000000000000000000000000000000e5f6a7b8",
			"artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
			# regal ignore:line-length
			"ref": "registry.io/repository/image@sha256:e5f6a7b800000000000000000000000000000000000000000000000e5f6a7b8",
		},
	]
	expected := [{"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	assertions.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Test SPDX SBOM discovery via OCI Referrers API
test_spdx_sboms_from_referrers if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/spdx+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	expected := [{"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}]
	assertions.assert_equal(sbom.spdx_sboms, expected) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _spdx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.oci.blob as mock_ec_oci_spdx_blob
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Test CycloneDX SBOM discovery via legacy tag-based conventions (.sbom suffix)
test_cyclonedx_sboms_from_tag_refs if {
	mock_tag_refs := [
		"registry.io/repository/image:sha256-284e3029.sig",
		"registry.io/repository/image:sha256-284e3029.sbom",
	]
	expected := [{"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	assertions.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.oci.image_manifest as _mock_sbom_manifest
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Test SPDX SBOM discovery via legacy tag-based conventions (.sbom suffix)
test_spdx_sboms_from_tag_refs if {
	mock_tag_refs := ["registry.io/repository/image:sha256-284e3029.sbom"]
	expected := [{"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}]
	assertions.assert_equal(sbom.spdx_sboms, expected) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _spdx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.oci.image_manifest as _mock_sbom_manifest
		with ec.oci.blob as mock_ec_oci_spdx_blob
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Test no SBOMs from referrers when artifact types don't match
test_no_sboms_from_unrelated_referrers if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 200,
		# regal ignore:line-length
		"digest": "sha256:e5f6a7b800000000000000000000000000000000000000000000000e5f6a7b8",
		"artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:e5f6a7b800000000000000000000000000000000000000000000000e5f6a7b8",
	}]
	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Test no SBOMs from tag refs when no .sbom suffix present
test_no_sboms_from_non_sbom_tag_refs if {
	mock_tag_refs := [
		"registry.io/repository/image:sha256-284e3029.sig",
		"registry.io/repository/image:sha256-284e3029.att",
	]
	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

_mock_sbom_manifest := {"layers": [{
	"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
	"digest": "sha256:f0cacc1a000000000000000000000000000000000000000000000000f0cacc1a",
	"size": 100,
}]}

# Tests for component_found_by_hermeto (CycloneDX)
test_component_found_by_hermeto_with_hermeto if {
	component := {"properties": [{"name": "hermeto:found_by", "value": "hermeto"}]}
	sbom.component_found_by_hermeto(component)
}

test_component_found_by_hermeto_with_cachi2 if {
	component := {"properties": [{"name": "cachi2:found_by", "value": "cachi2"}]}
	sbom.component_found_by_hermeto(component)
}

test_component_found_by_hermeto_not_found if {
	component := {"properties": [{"name": "other:property", "value": "other"}]}
	not sbom.component_found_by_hermeto(component)
}

test_component_found_by_hermeto_no_properties if {
	component := {}
	not sbom.component_found_by_hermeto(component)
}

# Tests for package_found_by_hermeto (SPDX)
test_package_found_by_hermeto_with_hermeto if {
	pkg := {"annotations": [{
		"annotator": "Tool: hermeto:jsonencoded",
		"annotationType": "OTHER",
	}]}
	sbom.package_found_by_hermeto(pkg)
}

test_package_found_by_hermeto_with_cachi2 if {
	pkg := {"annotations": [{
		"annotator": "Tool: cachi2:jsonencoded",
		"annotationType": "OTHER",
	}]}
	sbom.package_found_by_hermeto(pkg)
}

test_package_found_by_hermeto_not_found if {
	pkg := {"annotations": [{
		"annotator": "Tool: other:jsonencoded",
		"annotationType": "OTHER",
	}]}
	not sbom.package_found_by_hermeto(pkg)
}

test_package_found_by_hermeto_no_annotations if {
	pkg := {}
	not sbom.package_found_by_hermeto(pkg)
}

# Tests for is_registry_dependency
test_is_registry_dependency_cdx_plain if {
	parsed_purl := {"type": "npm", "name": "lib", "qualifiers": []}
	component := {"properties": [{"name": "hermeto:found_by", "value": "hermeto"}]}
	sbom.is_registry_dependency(parsed_purl, component)
}

test_is_registry_dependency_spdx_plain if {
	parsed_purl := {"type": "npm", "name": "lib", "qualifiers": []}
	pkg := {"annotations": [{
		"annotator": "Tool: hermeto:jsonencoded",
		"comment": "{\"name\":\"hermeto:found_by\",\"value\":\"hermeto\"}",
		"annotationDate": "2024-12-09T12:00:00Z",
		"annotationType": "OTHER",
	}]}
	sbom.is_registry_dependency(parsed_purl, pkg)
}

test_is_registry_dependency_unrelated_qualifiers if {
	parsed_purl := {"type": "maven", "name": "lib", "qualifiers": [{"key": "type", "value": "pom"}]}
	sbom.is_registry_dependency(parsed_purl, {})
}

test_is_registry_dependency_with_download_url if {
	parsed_purl := {"type": "generic", "name": "lib", "qualifiers": [{"key": "download_url", "value": "https://example.com/lib.tar.gz"}]}
	not sbom.is_registry_dependency(parsed_purl, {})
}

test_is_registry_dependency_with_vcs_url if {
	parsed_purl := {"type": "generic", "name": "lib", "qualifiers": [{"key": "vcs_url", "value": "https://github.com/example/lib.git"}]}
	not sbom.is_registry_dependency(parsed_purl, {})
}

test_is_registry_dependency_with_both if {
	parsed_purl := {"type": "generic", "name": "lib", "qualifiers": [
		{"key": "download_url", "value": "https://example.com/lib.tar.gz"},
		{"key": "vcs_url", "value": "https://github.com/example/lib.git"},
	]}
	not sbom.is_registry_dependency(parsed_purl, {})
}

test_is_registry_dependency_missing_qualifiers_field if {
	parsed_purl := {"type": "maven", "name": "lib"}
	sbom.is_registry_dependency(parsed_purl, {})
}

test_is_registry_dependency_cdx_bundled if {
	parsed_purl := {"type": "npm", "name": "lib", "qualifiers": []}
	component := {"properties": [
		{"name": "hermeto:found_by", "value": "hermeto"},
		{"name": "cdx:npm:package:bundled", "value": "true"},
	]}
	not sbom.is_registry_dependency(parsed_purl, component)
}

test_is_registry_dependency_spdx_bundled if {
	parsed_purl := {"type": "npm", "name": "lib", "qualifiers": []}
	pkg := {"annotations": [
		{
			"annotator": "Tool: hermeto:jsonencoded",
			"comment": "{\"name\":\"hermeto:found_by\",\"value\":\"hermeto\"}",
			"annotationDate": "2024-12-09T12:00:00Z",
			"annotationType": "OTHER",
		},
		{
			"annotator": "Tool: hermeto:jsonencoded",
			"comment": "{\"name\":\"cdx:npm:package:bundled\",\"value\":\"true\"}",
			"annotationDate": "2024-12-09T12:00:00Z",
			"annotationType": "OTHER",
		},
	]}
	not sbom.is_registry_dependency(parsed_purl, pkg)
}

test_is_registry_dependency_no_properties_or_annotations if {
	parsed_purl := {"type": "npm", "name": "lib", "qualifiers": []}
	sbom.is_registry_dependency(parsed_purl, {})
}

# Tests for disallowed_attribute_excepted

test_disallowed_attribute_excepted_match if {
	disallowed := {
		"name": "hermeto:pip:package:binary",
		"value": "true",
		"except_when": [{"purl_qualifier": "repository_url", "patterns": ["^https://console\\.redhat\\.com/api/pypi/.*"]}],
	}
	purl := "pkg:pypi/some-lib@1.0?repository_url=https://console.redhat.com/api/pypi/public-rhai/rhoai/3.5/simple/"
	sbom.disallowed_attribute_excepted(disallowed, purl)
}

test_disallowed_attribute_excepted_no_match if {
	disallowed := {
		"name": "hermeto:pip:package:binary",
		"value": "true",
		"except_when": [{"purl_qualifier": "repository_url", "patterns": ["^https://console\\.redhat\\.com/api/pypi/.*"]}],
	}
	purl := "pkg:pypi/some-lib@1.0?repository_url=https://pypi.org/simple/"
	not sbom.disallowed_attribute_excepted(disallowed, purl)
}

test_disallowed_attribute_excepted_missing_qualifier if {
	disallowed := {
		"name": "hermeto:pip:package:binary",
		"value": "true",
		"except_when": [{"purl_qualifier": "repository_url", "patterns": ["^https://console\\.redhat\\.com/api/pypi/.*"]}],
	}
	purl := "pkg:pypi/some-lib@1.0"
	not sbom.disallowed_attribute_excepted(disallowed, purl)
}

test_disallowed_attribute_excepted_no_except_when if {
	disallowed := {"name": "hermeto:pip:package:binary", "value": "true"}
	purl := "pkg:pypi/some-lib@1.0?repository_url=https://console.redhat.com/api/pypi/public-rhai/"
	not sbom.disallowed_attribute_excepted(disallowed, purl)
}

test_disallowed_attribute_excepted_empty_purl if {
	disallowed := {
		"name": "hermeto:pip:package:binary",
		"value": "true",
		"except_when": [{"purl_qualifier": "repository_url", "patterns": ["^https://console\\.redhat\\.com/.*"]}],
	}
	not sbom.disallowed_attribute_excepted(disallowed, "")
}

test_disallowed_attribute_excepted_multiple_patterns if {
	disallowed := {
		"name": "hermeto:pip:package:binary",
		"value": "true",
		"except_when": [{"purl_qualifier": "repository_url", "patterns": [
			"^https://console\\.redhat\\.com/api/pypi/.*",
			"^https://packages\\.redhat\\.com/pypi/.*",
		]}],
	}
	purl := "pkg:pypi/some-lib@1.0?repository_url=https://packages.redhat.com/pypi/rhoai/"
	sbom.disallowed_attribute_excepted(disallowed, purl)
}

test_disallowed_attribute_excepted_multiple_except_when if {
	disallowed := {
		"name": "hermeto:pip:package:binary",
		"value": "true",
		"except_when": [
			{"purl_qualifier": "repository_url", "patterns": ["^https://console\\.redhat\\.com/.*"]},
			{"purl_qualifier": "index_url", "patterns": ["^https://internal\\.example\\.com/.*"]},
		],
	}
	purl := "pkg:pypi/some-lib@1.0?index_url=https://internal.example.com/pypi/"
	sbom.disallowed_attribute_excepted(disallowed, purl)
}

test_golang_non_registry_empty_version_dependencies_excluded if {
	parsed_purl := {"type": "golang", "name": "localdep", "version": "", "qualifiers": []}
	sbom._is_local_gomod_dep(parsed_purl)
}

test_golang_non_registry_null_version_dependencies_excluded if {
	parsed_purl := {"type": "golang", "name": "localdep", "version": null, "qualifiers": []}
	sbom._is_local_gomod_dep(parsed_purl)
}

test_golang_non_registry_vcs_dependencies_excluded if {
	parsed_purl := {"type": "golang", "name": "localdep", "qualifiers": [{"key": "vcs_url", "value": "https://github.com/example/lib.git"}]}
	sbom._is_local_gomod_dep(parsed_purl)
}

test_golang_empty_present_vcs_url_not_excluded if {
	parsed_purl := {"type": "golang", "name": "localdep", "qualifiers": [{"key": "vcs_url", "value": ""}]}
	not sbom._is_local_gomod_dep(parsed_purl)
}

test_golang_null_present_vcs_url_not_excluded if {
	parsed_purl := {"type": "golang", "name": "localdep", "qualifiers": [{"key": "vcs_url", "value": null}]}
	not sbom._is_local_gomod_dep(parsed_purl)
}

test_golang_regular_package_not_rejected_as_local if {
	parsed_purl := {"type": "golang", "name": "adep", "version": "v0.0.1", "qualifiers": []}
	not sbom._is_local_gomod_dep(parsed_purl)
}

# --- SBOM signature verification tests ---

# Referrer SBOM excluded when signature verification fails
test_referrer_sbom_excluded_when_verification_fails if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.sigstore.verify_image as _mock_verify_image_failure
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Tag-ref SBOM excluded when signature verification fails
test_tag_ref_sbom_excluded_when_verification_fails if {
	mock_tag_refs := ["registry.io/repository/image:sha256-284e3029.sbom"]
	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.oci.image_manifest as _mock_sbom_manifest
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.sigstore.verify_image as _mock_verify_image_failure
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Referrer SBOM excluded when no "sbom" signing identity configured (default)
test_referrer_sbom_excluded_when_no_opts if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]

	# No "sbom" signing identity configured: SBOMs excluded even though the
	# verify mock would succeed. The absent identity triggers fail-closed behavior.
	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data as {}
}

# Tag-ref SBOM excluded when no "sbom" signing identity configured (default)
test_tag_ref_sbom_excluded_when_no_opts if {
	mock_tag_refs := ["registry.io/repository/image:sha256-284e3029.sbom"]
	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.oci.image_manifest as _mock_sbom_manifest
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data as {}
}

# Keyless verification: certificate_identity + OIDC issuer, no public_key
test_keyless_sbom_verification if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	keyless_opts := {
		"certificate_identity": "builder@example.com",
		"certificate_oidc_issuer": "https://accounts.example.com",
		"rekor_url": "https://rekor.example.com",
	}
	expected := [{"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	assertions.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
		with sbom._verified_sbom_attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": keyless_opts}}
}

test_attestation_sbom_discovered_by_policy_verifier if {
	expected := ["sbom from attestation"]

	assertions.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.sigstore.verify_attestation as _mock_verify_cyclonedx_attestation
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# Attached SBOM attestations are excluded when the "sbom" signing identity is
# not configured.
test_attestation_sbom_requires_signing_identity if {
	attestations := [{"statement": {
		"predicateType": "https://cyclonedx.org/bom",
		"predicate": {"bomFormat": "CycloneDX", "from": "attestation"},
	}}]

	assertions.assert_empty(sbom.cyclonedx_sboms) with input.attestations as attestations
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
}

test_attestation_sbom_signature_verification_failure if {
	attestations := [{"statement": {
		"predicateType": "https://spdx.dev/Document",
		"predicate": {"SPDXID": "SPDXRef-DOCUMENT"},
	}}]

	assertions.assert_empty(sbom.spdx_sboms) with input.attestations as attestations
		with input.image as _spdx_image
		with ec.sigstore.verify_attestation as _mock_verify_attestation_failure
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# A mixed verification result can retain successfully parsed attestations while
# reporting failure for another attestation. Reject the entire result so partial
# verification cannot admit an SBOM.
test_attestation_sbom_partial_verification_failure if {
	assertions.assert_empty(sbom.cyclonedx_sboms) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.sigstore.verify_attestation as _mock_verify_attestation_partial_failure
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
}

# The digest-pinned SBOM_BLOB_URL in verified provenance remains trusted and
# does not require the "sbom" signing identity.
test_pipelinerun_sbom_unaffected_by_sbom_opts if {
	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:284e3029000000000000000000000000000000000000000000000000284e3029"}, # regal ignore:line-length
				{"name": "IMAGE_URL", "type": "string", "value": "registry.io/repository/image:latest"},
				{"name": "SBOM_BLOB_URL", "type": "string", "value": "registry.io/repository/image@sha256:f0cacc1a"},
			]}]},
		},
	}}]

	expected := [{"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	assertions.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as _cyclonedx_image
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
}

# --- Tests for the "sbom" signing identity validation ---

# A valid key-based identity produces no signing_identities.sbom errors.
test_sbom_identity_valid_public_key if {
	opts := {"public_key": "key", "ignore_rekor": true}
	errors := sbom.rule_data_errors with data.rule_data__configuration__ as {"signing_identities": {"sbom": opts}}
		with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
	count(_sbom_identity_errors(errors)) == 0
}

# A valid keyless identity produces no signing_identities.sbom errors.
test_sbom_identity_valid_keyless if {
	opts := {
		"certificate_identity": "id@example.com",
		"certificate_oidc_issuer": "https://accounts.example.com",
		"rekor_url": "https://rekor.example.com",
	}
	errors := sbom.rule_data_errors with data.rule_data__configuration__ as {"signing_identities": {"sbom": opts}}
		with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
	count(_sbom_identity_errors(errors)) == 0
}

# When no "sbom" identity is configured, validation is silent (fail-closed).
test_sbom_identity_absent_no_errors if {
	errors := sbom.rule_data_errors with data.rule_data as {}
		with data.rule_data__configuration__ as {}
		with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
	count(_sbom_identity_errors(errors)) == 0
}

# An incomplete identity is rejected by the shared sigstore validator.
test_sbom_identity_incomplete_errors if {
	opts := {"public_key": "key"}
	errors := sbom.rule_data_errors with data.rule_data__configuration__ as {"signing_identities": {"sbom": opts}}
		with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
	count(_sbom_identity_errors(errors)) > 0
}

# A non-object entry is reported as a malformed identity.
test_sbom_identity_not_an_object if {
	errors := sbom.rule_data_errors with data.rule_data__configuration__ as {"signing_identities": {"sbom": "not-an-object"}}
		with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
	matching := {e | some e in errors; contains(e.message, "has unexpected format: expected an object")}
	count(matching) == 1
}

# The "sbom" identity is optional: a configured map without it produces no
# "missing key" warning (unlike the required rh-release identity).
test_sbom_identity_missing_key_silent if {
	d := {"signing_identities": {"rh-release": {"public_key": "key", "ignore_rekor": true}}}
	errors := sbom.rule_data_errors with data.rule_data__configuration__ as d
		with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
	matching := {e | some e in errors; contains(e.message, "does not contain the expected key")}
	count(matching) == 0
}

_sbom_identity_errors(errors) := {e | some e in errors; contains(e.message, "signing_identities.sbom")}

# --- Tests for signature_verification_errors ---

test_verification_error_surfaced_for_referrers if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	errors := sbom.signature_verification_errors with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.sigstore.verify_attestation as _mock_verify_attestation_success
		with ec.sigstore.verify_image as _mock_verify_image_failure
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
	count(errors) == 1
	some error in errors
	contains(error, "SBOM referrer signature verification failed")
}

test_verification_error_surfaced_for_tag_refs if {
	mock_tag_refs := ["registry.io/repository/image:sha256-abc123.sbom"]
	errors := sbom.signature_verification_errors with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.sigstore.verify_attestation as _mock_verify_attestation_success
		with ec.sigstore.verify_image as _mock_verify_image_failure
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
	count(errors) == 1
	some error in errors
	contains(error, "SBOM tag ref signature verification failed")
}

test_no_verification_errors_when_verify_succeeds if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	errors := sbom.signature_verification_errors with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.sigstore.verify_attestation as _mock_verify_attestation_success
		with ec.sigstore.verify_image as _mock_verify_image_success
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
	count(errors) == 0
}

test_unrelated_referrer_excluded_from_verification_errors if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.dev.cosign.simplesigning.v1+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	errors := sbom.signature_verification_errors with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.sigstore.verify_attestation as _mock_verify_attestation_success
		with ec.sigstore.verify_image as _mock_verify_image_failure
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
	count(errors) == 0
}

test_verification_error_surfaced_for_attestations if {
	errors := sbom.signature_verification_errors with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
		with ec.sigstore.verify_attestation as _mock_verify_attestation_failure
		with data.rule_data__configuration__ as {"signing_identities": {"sbom": _mock_sbom_opts}}
	count(errors) == 1
	some error in errors
	contains(error, "SBOM attestation signature verification failed")
}

test_no_verification_errors_when_no_opts if {
	mock_referrers := [{
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"size": 100,
		# regal ignore:line-length
		"digest": "sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
		"artifactType": "application/vnd.cyclonedx+json",
		# regal ignore:line-length
		"ref": "registry.io/repository/image@sha256:a1b2c3d400000000000000000000000000000000000000000000000a1b2c3d4",
	}]
	errors := sbom.signature_verification_errors with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.sigstore.verify_image as _mock_verify_image_failure
		with data.rule_data as {}
	count(errors) == 0
}

_mock_sbom_opts := {"public_key": "test-signing-key", "ignore_rekor": true}

_mock_verify_cyclonedx_attestation(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [{"statement": {
		"predicateType": "https://cyclonedx.org/bom",
		"predicate": "sbom from attestation",
	}}],
}

_mock_verify_spdx_attestation(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [{"statement": {
		"predicateType": "https://spdx.dev/Document",
		"predicate": "sbom from attestation",
	}}],
}

_mock_verify_attestation_failure(_, _) := {
	"success": false,
	"errors": ["verification failed"],
	"attestations": [],
}

_mock_verify_attestation_success(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [],
}

_mock_verify_attestation_partial_failure(_, _) := {
	"success": false,
	"errors": ["parsing another attestation failed"],
	"attestations": [{"statement": {
		"predicateType": "https://cyclonedx.org/bom",
		"predicate": "partially verified sbom",
	}}],
}

_mock_verify_image_success(_, _) := {"errors": []}

_mock_verify_image_failure(_, _) := {"errors": ["verification failed"]}
