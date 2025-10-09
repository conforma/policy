package slsa_build_build_service_test

import rego.v1

import data.lib
import data.slsa_build_build_service

test_all_good if {
	builder_id := lib.rule_data("allowed_builder_ids")[0]
	lib.assert_empty(slsa_build_build_service.deny) with input.attestations as [_mock_attestation(builder_id)]

	lib.assert_empty(slsa_build_build_service.deny) with input.attestations as [_mock_slsa_v1_attestation(builder_id)]
}

test_slsa_builder_id_found if {
	attestations := [
		# Missing predicate.builder.id
		{"statement": {"predicate": {
			"builder": {},
			"buildType": lib.tekton_pipeline_run,
		}}},
		# Missing predicate.builder
		{"statement": {"predicate": {"buildType": lib.tekton_pipeline_run}}},
	]

	slsa_v1_attestations := [
		# Missing predicate.runDetails.builder.id
		{"statement": {
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {
				"buildDefinition": {
					"buildType": "https://tekton.dev/chains/v2/slsa",
					"externalParameters": {"runSpec": {"pipelineSpec": {}}},
				},
				"runDetails": {"builder": {}},
			},
		}},
		# Missing predicate.runDetails.builder
		{"statement": {
			"predicateType": "https://slsa.dev/provenance/v1",
			"predicate": {
				"buildDefinition": {
					"buildType": "https://tekton.dev/chains/v2/slsa",
					"externalParameters": {"runSpec": {"pipelineSpec": {}}},
				},
				"runDetails": {},
			},
		}},
	]

	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_found",
		"msg": "Builder ID not set in attestation",
	}}

	lib.assert_equal_results(expected, slsa_build_build_service.deny) with input.attestations as attestations

	lib.assert_equal_results(expected, slsa_build_build_service.deny) with input.attestations as slsa_v1_attestations
}

test_accepted_slsa_builder_id if {
	builder_id := "https://notket.ved/sniahc/2v"
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_accepted",
		"msg": "Builder ID \"https://notket.ved/sniahc/2v\" is unexpected",
	}}
	lib.assert_equal_results(
		expected,
		slsa_build_build_service.deny,
	) with input.attestations as [_mock_attestation(builder_id)]

	lib.assert_equal_results(
		expected,
		slsa_build_build_service.deny,
	) with input.attestations as [_mock_slsa_v1_attestation(builder_id)]
}

test_rule_data_format if {
	d := {"allowed_builder_ids": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

	expected := {
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided",
			"msg": "Rule data allowed_builder_ids has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided",
			"msg": "Rule data allowed_builder_ids has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data as d
		with input.attestations as [_mock_attestation("foo")]
}

_mock_attestation(builder_id) := {"statement": {"predicate": {
	"builder": {"id": builder_id},
	"buildType": lib.tekton_pipeline_run,
}}}

_mock_slsa_v1_attestation(builder_id) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		},
		"runDetails": {"builder": {"id": builder_id}},
	},
}}
