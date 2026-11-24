package rpm_signature_test

import rego.v1

import data.lib.assertions
import data.lib_test
import data.rpm_signature

test_success if {
	result_value := {"keys": {"abcdef0123456789": 1, "ABCDEF0123456789": 2, "unsigned": 0}}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	assertions.assert_empty(rpm_signature.deny) with input.attestations as attestations
		with data.rule_data.allowed_rpm_signature_keys as ["abcdef0123456789", "ABCDEF0123456789"]
}

test_disallowed_key if {
	result_value := {"keys": {"abcdef0123456789": 1, "ABCDEF0123456789": 2}}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {
		{
			"code": "rpm_signature.allowed",
			"msg": "Signing key \"ABCDEF0123456789\" is not one of the allowed keys: [\"bcdef0123456789a\"]",
			"term": "ABCDEF0123456789",
		},
		{
			"code": "rpm_signature.allowed",
			"msg": "Signing key \"abcdef0123456789\" is not one of the allowed keys: [\"bcdef0123456789a\"]",
			"term": "abcdef0123456789",
		},
	}
	assertions.assert_equal_results(rpm_signature.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_signature_keys as ["bcdef0123456789a"]
}

test_can_allow_unsigned if {
	result_value := {"keys": {"unsigned": 10}}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	assertions.assert_empty(rpm_signature.deny) with input.attestations as attestations
		with data.rule_data.allowed_rpm_signature_keys as ["unsigned"]
}

test_task_result_invalid_format if {
	result_value := {"keys": {"abcdef0123456789": "1"}, "ignored": true}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {{
		"code": "rpm_signature.result_format",
		"msg": "Task result has unexpected format: keys.abcdef0123456789: Invalid type. Expected: integer, given: string",
	}}
	assertions.assert_equal_results(rpm_signature.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_signature_keys as ["abcdef0123456789"]
}

test_rule_data_provided if {
	d := {"allowed_rpm_signature_keys": [
		# Wrong data type
		1,
		# Duplicated items
		"abcdef0123456789",
		"abcdef0123456789",
	]}

	expected := {
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": "Rule data has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided_v2",
			"msg": "Rule data has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": "Unexpected format of signing key '\\x01'",
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": "Rule data has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided_v2",
			"msg": "Rule data has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(rpm_signature.deny, expected) with data.rule_data as d
}

test_rule_data_not_provided if {
	expected := {
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": "Rule data has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided_v2",
			"msg": "Rule data has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(rpm_signature.deny, expected) with data.rule_data as {}
}

# A present but scalar `allowed_rpm_signature_keys` value must produce a format
# rejection from the v2 rule instead of silently skipping the check. The legacy
# rule_data_provided is untouched: a builtin error in its schema validation
# still suppresses its result, which is the gap rule_data_provided_v2 closes.
test_rule_data_provided_v2_scalar_rejected if {
	expected_string := {{
		"code": "rpm_signature.rule_data_provided_v2",
		"msg": "Rule data has unexpected format: (Root): Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(rpm_signature.deny, expected_string) with data.rule_data.allowed_rpm_signature_keys as "abcdef0123456789"

	expected_number := {{
		"code": "rpm_signature.rule_data_provided_v2",
		"msg": "Rule data has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(rpm_signature.deny, expected_number) with data.rule_data.allowed_rpm_signature_keys as 1
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_rule_data_provided_v2_precedence if {
	expected := {{
		"code": "rpm_signature.rule_data_provided_v2",
		"msg": "Rule data has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}

	assertions.assert_equal_results(rpm_signature.deny, expected) with data.rule_data_custom as {"allowed_rpm_signature_keys": 1}
		with data.rule_data as {"allowed_rpm_signature_keys": ["abcdef0123456789"]}
}

# A null value is rejected by both rules with the shared helper's argument
# diagnostic: current behavior, locked in.
test_rule_data_null_rejected_by_both if {
	msg := "Rule data has unexpected format: Provided empty document for schema validation"

	expected := {
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": msg,
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided_v2",
			"msg": msg,
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(rpm_signature.deny, expected) with data.rule_data.allowed_rpm_signature_keys as null
}

# A wrong-container value is rejected by both rules. The legacy rule also
# reports the object's values as badly formatted signing keys, since its
# signing-key check iterates the value: current behavior, locked in.
test_rule_data_not_an_array if {
	msg := "Rule data has unexpected format: (Root): Invalid type. Expected: array, given: object"

	expected := {
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": msg,
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided_v2",
			"msg": msg,
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": "Unexpected format of signing key \"bacon\"",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(rpm_signature.deny, expected) with data.rule_data.allowed_rpm_signature_keys as {"chunky": "bacon"}
}

# A valid list, including the special "unsigned" value, produces no format
# violations from either rule.
test_rule_data_valid if {
	assertions.assert_empty(rpm_signature.deny) with data.rule_data.allowed_rpm_signature_keys as ["unsigned", "abcdef0123456789"]
}

# A schema-valid list with a badly formatted signing key is only reported by
# the legacy rule: the signing-key format check has no v2 twin.
test_rule_data_invalid_signing_key_legacy_only if {
	expected := {{
		"code": "rpm_signature.rule_data_provided",
		"msg": "Unexpected format of signing key \"xyz\"",
		"severity": "failure",
	}}

	assertions.assert_equal_results(rpm_signature.deny, expected) with data.rule_data.allowed_rpm_signature_keys as ["xyz"]
}

_attestation_v0_2(result_value) := lib_test.att_mock_helper_ref(
	rpm_signature._rpms_data_result_name,
	result_value,
	"spam_v0_2",
	_bundle,
)

_attestation_v1_0(result_value) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {
				"params": [],
				"pipelineSpec": {"tasks": []},
			}},
		},
		"runDetails": {"byproducts": [{
			"name": concat("-", ["taskRunResults/spam_v1", rpm_signature._rpms_data_result_name]),
			"value": result_value,
		}]},
	},
}}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
