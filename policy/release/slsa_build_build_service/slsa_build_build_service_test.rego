package slsa_build_build_service_test

import rego.v1

import data.lib
import data.lib.assertions
import data.lib.rule_data
import data.slsa_build_build_service

test_all_good if {
	builder_id := rule_data.get("allowed_builder_ids")[0]
	assertions.assert_empty(slsa_build_build_service.deny) with input.attestations as [_mock_slsa_v02_attestation(builder_id)]

	assertions.assert_empty(slsa_build_build_service.deny) with input.attestations as [_mock_slsa_v1_attestation(builder_id)]
}

test_slsa_builder_id_found_v02_missing_id if {
	# Test v0.2 attestation with missing predicate.builder.id
	attestation := {"statement": {"predicate": {
		"builder": {},
		"buildType": lib.tekton_pipeline_run,
	}}}
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_found",
		"msg": "Builder ID not set in attestation",
	}}
	assertions.assert_equal_results(expected, slsa_build_build_service.deny) with input.attestations as [attestation]
}

test_slsa_builder_id_found_v02_missing_builder if {
	# Test v0.2 attestation with missing predicate.builder
	attestation := {"statement": {"predicate": {"buildType": lib.tekton_pipeline_run}}}
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_found",
		"msg": "Builder ID not set in attestation",
	}}
	assertions.assert_equal_results(expected, slsa_build_build_service.deny) with input.attestations as [attestation]
}

test_slsa_builder_id_found_v1_missing_id if {
	# Test v1.0 attestation with missing predicate.runDetails.builder.id
	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {
				"buildType": "https://tekton.dev/chains/v2/slsa",
				"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			},
			"runDetails": {"builder": {}},
		},
	}}
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_found",
		"msg": "Builder ID not set in attestation",
	}}
	assertions.assert_equal_results(expected, slsa_build_build_service.deny) with input.attestations as [attestation]
}

test_slsa_builder_id_found_v1_missing_builder if {
	# Test v1.0 attestation with missing predicate.runDetails.builder
	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {
			"buildDefinition": {
				"buildType": "https://tekton.dev/chains/v2/slsa",
				"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			},
			"runDetails": {},
		},
	}}
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_found",
		"msg": "Builder ID not set in attestation",
	}}
	assertions.assert_equal_results(expected, slsa_build_build_service.deny) with input.attestations as [attestation]
}

test_accepted_slsa_builder_id if {
	builder_id := "https://notket.ved/sniahc/2v"
	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_accepted",
		"msg": "Builder ID \"https://notket.ved/sniahc/2v\" is unexpected",
	}}
	assertions.assert_equal_results(
		expected,
		slsa_build_build_service.deny,
	) with input.attestations as [_mock_slsa_v02_attestation(builder_id)]

	assertions.assert_equal_results(
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

	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data as d
		with input.attestations as [_mock_slsa_v02_attestation("foo")]
}

_mock_slsa_v02_attestation(builder_id) := {"statement": {"predicate": {
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
