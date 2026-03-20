package lib.sbom_test

import rego.v1

import data.lib
import data.lib.sbom

test_all_sboms if {
	expected := ["hurricane", "tornado", "spandex", "latex"]
	lib.assert_equal(sbom.all_sboms, expected) with sbom.cyclonedx_sboms as ["hurricane", "tornado"]
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
						"value": "registry.io/repository/image@sha256:f0cacc1a00000000000000000000000000000000000000000000000f0cacc1a0",
					},
				]}]},
			},
		}},
	]
	expected := ["sbom from attestation", {"sbom": "from oci blob", "bomFormat": "CycloneDX"}]
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
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
						"value": "registry.io/repository/image@sha256:f0cacc1a00000000000000000000000000000000000000000000000f0cacc1a0",
					},
				]}]},
			},
		}},
	]
	expected := ["sbom from attestation", {"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}]
	lib.assert_equal(sbom.spdx_sboms, expected) with input.attestations as attestations
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
					"value": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1a00000000000000000000000000000000000000000000000f0cacc1a0",
				},
			]}]},
		}}},
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:1111111000000000000000000000000000000000000000000000000001111111",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.io/repository/image:latest",
				},
				{
					"name": "SBOM_BLOB_URL",
					"type": "string",
					"value": "registry.io/repository/image@sha256:f0cacc1b00000000000000000000000000000000000000000000000f0cacc1b0",
				},
			]}]},
		}}},
	]

	lib.assert_equal(sbom.all_sboms, []) with input.attestations as attestations
		# regal ignore:line-length
with 		input.image as {"ref": "registry.io/repository/image@sha256:284e3029000000000000000000000000000000000000000000000000284e3029"}
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
	lib.assert_equal(sbom.image_ref_from_purl(purl), image_ref)
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
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
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
	lib.assert_equal(sbom.spdx_sboms, expected) with input.attestations as []
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
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
}

# Test SPDX SBOM discovery via legacy tag-based conventions (.sbom suffix)
test_spdx_sboms_from_tag_refs if {
	mock_tag_refs := ["registry.io/repository/image:sha256-284e3029.sbom"]
	expected := [{"sbom": "from oci blob", "SPDXID": "SPDXRef-DOCUMENT"}]
	lib.assert_equal(sbom.spdx_sboms, expected) with input.attestations as []
		with input.image as _spdx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
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
	lib.assert_equal(sbom.all_sboms, []) with input.attestations as []
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
	lib.assert_equal(sbom.all_sboms, []) with input.attestations as []
		with input.image as _cyclonedx_image
		with ec.oci.image_referrers as []
		with ec.oci.image_tag_refs as mock_tag_refs
}
