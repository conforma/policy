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
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
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
		with ec.oci.blob as mock_ec_oci_spdx_blob
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as []
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
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
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
		with input.image as _spdx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
		with ec.oci.blob as mock_ec_oci_spdx_blob
}

# Test CycloneDX SBOM discovery via legacy tag-based conventions (.sbom suffix)
test_cyclonedx_sboms_from_tag_refs if {
	mock_tag_refs := [
		"registry.io/repository/image:sha256-284e3029.sig",
		"registry.io/repository/image:sha256-284e3029.sbom",
	]
	expected := [{"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	assertions.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.oci.image_manifest as _mock_sbom_manifest
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
}

# Test SPDX SBOM discovery via legacy tag-based conventions (.sbom suffix)
test_spdx_sboms_from_tag_refs if {
	mock_tag_refs := ["registry.io/repository/image:sha256-284e3029.sbom"]
	expected := [{"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}]
	assertions.assert_equal(sbom.spdx_sboms, expected) with input.attestations as []
		with input.image as _spdx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.oci.image_manifest as _mock_sbom_manifest
		with ec.oci.blob as mock_ec_oci_spdx_blob
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
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.image_tag_refs as []
}

# Test no SBOMs from tag refs when no .sbom suffix present
test_no_sboms_from_non_sbom_tag_refs if {
	mock_tag_refs := [
		"registry.io/repository/image:sha256-284e3029.sig",
		"registry.io/repository/image:sha256-284e3029.att",
	]
	assertions.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
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
test_is_registry_dependency_no_qualifiers if {
	parsed_purl := {"type": "maven", "name": "lib", "qualifiers": []}
	sbom.is_registry_dependency(parsed_purl)
}

test_is_registry_dependency_unrelated_qualifiers if {
	parsed_purl := {"type": "maven", "name": "lib", "qualifiers": [{"key": "type", "value": "pom"}]}
	sbom.is_registry_dependency(parsed_purl)
}

test_is_registry_dependency_with_download_url if {
	parsed_purl := {"type": "generic", "name": "lib", "qualifiers": [{"key": "download_url", "value": "https://example.com/lib.tar.gz"}]}
	not sbom.is_registry_dependency(parsed_purl)
}

test_is_registry_dependency_with_vcs_url if {
	parsed_purl := {"type": "generic", "name": "lib", "qualifiers": [{"key": "vcs_url", "value": "https://github.com/example/lib.git"}]}
	not sbom.is_registry_dependency(parsed_purl)
}

test_is_registry_dependency_with_both if {
	parsed_purl := {"type": "generic", "name": "lib", "qualifiers": [
		{"key": "download_url", "value": "https://example.com/lib.tar.gz"},
		{"key": "vcs_url", "value": "https://github.com/example/lib.git"},
	]}
	not sbom.is_registry_dependency(parsed_purl)
}

test_is_registry_dependency_missing_qualifiers_field if {
	parsed_purl := {"type": "maven", "name": "lib"}
	sbom.is_registry_dependency(parsed_purl)
}
