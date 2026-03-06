package lib.konflux_test

import rego.v1

import data.lib
import data.lib.konflux

test_is_image_index if {
	konflux.is_validating_image_index with input.attestations as [_attestation]
		with input.image.ref as "registry.local/ham@sha256:fff"
}

test_is_image_index_unknown_digest if {
	not konflux.is_validating_image_index with input.attestations as [_attestation]
		with input.image.ref as "registry.local/ham@sha256:bbb"
}

test_is_image_index_empty_images if {
	att := json.patch(
		_attestation,
		[{"op": "add", "path": "/statement/predicate/buildConfig/tasks/0/results/0/value", "value": ""}],
	)
	not konflux.is_validating_image_index with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:fff"
}

_attestation := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{"results": [
			{
				"name": "IMAGES",
				"type": "string",
				"value": "registry.local/spam@sha256:abc, registry.local/bacon@sha256:bcd",
			},
			{
				"name": "IMAGE_URL",
				"type": "string",
				"value": "registry.local/eggs:latest",
			},
			{
				"name": "IMAGE_DIGEST",
				"type": "string",
				"value": "sha256:fff",
			},
		]}]},
	},
}}
