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
						"value": "sha256:284e3029",
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
	lib.assert_equal(sbom.cyclonedx_sboms, expected) with input.attestations as attestations
		with input.image as _cyclonedx_image
		with ec.oci.blob as mock_ec_oci_cyclonedx_blob
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
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
						"value": "sha256:284e3029",
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
	lib.assert_equal(sbom.spdx_sboms, expected) with input.attestations as attestations
		with input.image as _spdx_image
		with ec.oci.blob as mock_ec_oci_spdx_blob
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
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

	lib.assert_equal(sbom.all_sboms, []) with input.attestations as attestations
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
		with ec.oci.blob as ""
		with ec.oci.descriptor as {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
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
	"ref": "registry.io/repository/image@sha256:284e3029",
	"config": {"Labels": {"vendor": "Red Hat, Inc."}},
}

_spdx_image := {
	"ref": "registry.io/repository/image@sha256:284e3029",
	"config": {"Labels": {"vendor": "Red Hat, Inc."}},
}
