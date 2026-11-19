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
			"code": "slsa_build_build_service.allowed_builder_ids_provided_v2",
			"msg": "Rule data allowed_builder_ids has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided",
			"msg": "Rule data allowed_builder_ids has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided_v2",
			"msg": "Rule data allowed_builder_ids has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data as d
		with input.attestations as [_mock_slsa_v02_attestation("foo")]
}

# A present but scalar `allowed_builder_ids` value must produce a format
# rejection from the v2 rule instead of silently skipping the check. The legacy
# allowed_builder_ids_provided is untouched: a builtin error in its schema
# validation still suppresses its result, which is the gap the v2 rule closes.
test_allowed_builder_ids_provided_v2_scalar_rejected if {
	expected := {{
		"code": "slsa_build_build_service.allowed_builder_ids_provided_v2",
		"msg": "Rule data allowed_builder_ids has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}

	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data.allowed_builder_ids as 1
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_allowed_builder_ids_provided_v2_precedence if {
	expected := {{
		"code": "slsa_build_build_service.allowed_builder_ids_provided_v2",
		"msg": "Rule data allowed_builder_ids has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}

	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data_custom as {"allowed_builder_ids": 1}
		with data.rule_data as {"allowed_builder_ids": ["https://tekton.dev/chains/v2"]}
}

# A null value is rejected by both rules with the shared helper's argument
# diagnostic: current behavior, locked in.
test_rule_data_null_rejected_by_both if {
	msg := "Rule data allowed_builder_ids has unexpected format: Provided empty document for schema validation"

	expected := {
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided",
			"msg": msg,
			"severity": "failure",
		},
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided_v2",
			"msg": msg,
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data.allowed_builder_ids as null
}

# A wrong-container value is rejected by both rules.
test_rule_data_not_an_array if {
	msg := "Rule data allowed_builder_ids has unexpected format: (Root): Invalid type. Expected: array, given: object"

	expected := {
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided",
			"msg": msg,
			"severity": "failure",
		},
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided_v2",
			"msg": msg,
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data.allowed_builder_ids as {"chunky": "bacon"}
}

# An explicit empty array is invalid: the list must be nonempty. Both rules
# reject it.
test_rule_data_empty_rejected_by_both if {
	msg := "Rule data allowed_builder_ids has unexpected format: (Root): Array must have at least 1 items"

	expected := {
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided",
			"msg": msg,
			"severity": "failure",
		},
		{
			"code": "slsa_build_build_service.allowed_builder_ids_provided_v2",
			"msg": msg,
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data.allowed_builder_ids as []
}

# The key absent from every configured source resolves to the valid default
# builder id list, so no format violations are reported.
test_rule_data_absent_uses_default if {
	assertions.assert_empty(slsa_build_build_service.deny) with data.rule_data as {}
}

# A valid custom list still reaches the consumer rules: a matching builder id
# passes and a nonmatching one is denied, with no format violations.
test_rule_data_valid_consumer_reached if {
	assertions.assert_empty(slsa_build_build_service.deny) with data.rule_data.allowed_builder_ids as ["https://custom.builder/v1"]
		with input.attestations as [_mock_slsa_v02_attestation("https://custom.builder/v1")]

	expected := {{
		"code": "slsa_build_build_service.slsa_builder_id_accepted",
		"msg": "Builder ID \"https://another.builder/v9\" is unexpected",
	}}
	assertions.assert_equal_results(slsa_build_build_service.deny, expected) with data.rule_data.allowed_builder_ids as ["https://custom.builder/v1"]
		with input.attestations as [_mock_slsa_v02_attestation("https://another.builder/v9")]
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
