package attestation_type_test

import rego.v1

import data.attestation_type

import data.lib
import data.lib.assertions

good_type := "https://in-toto.io/Statement/v0.1"

good_type_v1 := "https://in-toto.io/Statement/v1"

bad_type := "https://in-toto.io/Statement/v0.0.9999999"

mock_data(att_type) := [{"statement": {
	"_type": att_type,
	"predicate": {"buildType": lib.tekton_pipeline_run},
}}]

test_allow_when_permitted if {
	assertions.assert_empty(attestation_type.deny) with input.attestations as mock_data(good_type)
	assertions.assert_empty(attestation_type.deny) with input.attestations as mock_data(good_type_v1)
}

test_deny_when_not_permitted if {
	expected_msg := sprintf("Unknown attestation type '%s'", [bad_type])
	assertions.assert_equal_results(attestation_type.deny, {{
		"code": "attestation_type.known_attestation_type",
		"msg": expected_msg,
	}}) with input.attestations as mock_data(bad_type)
}

test_deny_when_pipelinerun_attestation_founds if {
	expected := {{
		"code": "attestation_type.pipelinerun_attestation_found",
		"msg": "Missing pipelinerun attestation",
	}}
	attestations := [
		{"statement": {
			"_type": good_type,
			"predicate": {"buildType": "tekton.dev/v1beta1/TaskRun"},
		}},
		{"statement": {
			"_type": good_type,
			"predicate": {"buildType": "spam/spam/eggs/spam"},
		}},
	]
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as attestations
}

test_deny_deprecated_policy_attestation_format if {
	expected := {
		{
			"code": "attestation_type.deprecated_policy_attestation_format",
			"msg": "Deprecated policy attestation format found",
		},
		{
			"code": "attestation_type.pipelinerun_attestation_found",
			"msg": "Missing pipelinerun attestation",
		},
	}
	attestations := [{
		"_type": good_type,
		"predicate": {"buildType": lib.tekton_pipeline_run},
	}]
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as attestations
}

test_rule_data_validation if {
	d := {"known_attestation_types": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

	expected := {
		{
			"code": "attestation_type.known_attestation_types_provided",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "attestation_type.known_attestation_types_provided",
			"msg": "Rule data known_attestation_types has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(attestation_type.deny, expected) with data.rule_data as d
		with input.attestations as mock_data("foo")
}

# RA06-KNOWN-OBJECT-001: a present but scalar `known_attestation_types` value must produce a
# format rejection from the v2 rule instead of silently skipping the check. The legacy
# known_attestation_types_provided is untouched: a builtin error in its schema validation still
# suppresses its result, which is the gap the v2 rule closes. The consumer rule keeps its
# current behavior and reports the unknown type against the unusable list.
test_known_attestation_types_provided_v2_scalar_rejected if {
	expected := {
		{
			"code": "attestation_type.known_attestation_type",
			"msg": sprintf("Unknown attestation type '%s'", [good_type]),
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): Invalid type. Expected: array, given: integer",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data(good_type)
		with data.rule_data as {"known_attestation_types": 1}
}

# A string value is malformed even when it contains JSON text for a valid
# array: JSON text in a scalar must not be mistaken for a native array.
test_known_attestation_types_provided_v2_string_rejected if {
	expected := {
		{
			"code": "attestation_type.known_attestation_type",
			"msg": sprintf("Unknown attestation type '%s'", [good_type]),
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data(good_type)
		with data.rule_data as {"known_attestation_types": "x"}

	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data(good_type)
		with data.rule_data as {"known_attestation_types": "[\"foo\"]"}
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data. The consumer rule keeps its current
# behavior and evaluates against the unusable high-priority value.
test_known_attestation_types_provided_v2_precedence if {
	expected := {
		{
			"code": "attestation_type.known_attestation_type",
			"msg": sprintf("Unknown attestation type '%s'", [good_type]),
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): Invalid type. Expected: array, given: integer",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data(good_type)
		with data.rule_data_custom as {"known_attestation_types": 1}
		with data.rule_data as {"known_attestation_types": [good_type]}
}

# Shape controls locking in the current format contract: null and wrong-container values are
# rejected by both rules with identical messages, and an explicit empty array is invalid
# (unlike a missing key, which resolves to the defaults in lib.rule_data).
test_known_attestation_types_null_rejected if {
	expected := {
		{
			"code": "attestation_type.known_attestation_type",
			"msg": sprintf("Unknown attestation type '%s'", [good_type]),
		},
		{
			"code": "attestation_type.known_attestation_types_provided",
			"msg": "Rule data known_attestation_types has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data(good_type)
		with data.rule_data as {"known_attestation_types": null}
}

test_known_attestation_types_wrong_container_rejected if {
	expected := {
		{
			"code": "attestation_type.known_attestation_type",
			"msg": sprintf("Unknown attestation type '%s'", [good_type]),
		},
		{
			"code": "attestation_type.known_attestation_types_provided",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data(good_type)
		with data.rule_data as {"known_attestation_types": {"foo": "bar"}}
}

test_known_attestation_types_empty_array_rejected if {
	expected := {
		{
			"code": "attestation_type.known_attestation_type",
			"msg": sprintf("Unknown attestation type '%s'", [good_type]),
		},
		{
			"code": "attestation_type.known_attestation_types_provided",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "attestation_type.known_attestation_types_provided_v2",
			"msg": "Rule data known_attestation_types has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data(good_type)
		with data.rule_data as {"known_attestation_types": []}
}

# A missing key resolves to the valid defaults in lib.rule_data, so neither format rule fires.
test_known_attestation_types_absent_uses_defaults if {
	assertions.assert_empty(attestation_type.deny) with input.attestations as mock_data(good_type)
		with data.rule_data as {}
}

# Valid data must still reach the consumer rule: a matching type passes and an unknown type
# is denied.
test_known_attestation_type_with_custom_data if {
	assertions.assert_empty(attestation_type.deny) with input.attestations as mock_data("custom-type")
		with data.rule_data as {"known_attestation_types": ["custom-type"]}

	expected := {{
		"code": "attestation_type.known_attestation_type",
		"msg": "Unknown attestation type 'other-type'",
	}}
	assertions.assert_equal_results(attestation_type.deny, expected) with input.attestations as mock_data("other-type")
		with data.rule_data as {"known_attestation_types": ["custom-type"]}
}
