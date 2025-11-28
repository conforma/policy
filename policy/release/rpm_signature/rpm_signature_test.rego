package rpm_signature_test

import rego.v1

import data.lib
import data.lib.tekton_test
import data.lib_test
import data.rpm_signature

test_success if {
	result_value := {"keys": {"abcdef0123456789": 1, "ABCDEF0123456789": 2, "unsigned": 0}}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	lib.assert_empty(rpm_signature.deny) with input.attestations as attestations
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
	lib.assert_equal_results(rpm_signature.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_signature_keys as ["bcdef0123456789a"]
}

test_can_allow_unsigned if {
	result_value := {"keys": {"unsigned": 10}}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	lib.assert_empty(rpm_signature.deny) with input.attestations as attestations
		with data.rule_data.allowed_rpm_signature_keys as ["unsigned"]
}

test_task_result_invalid_format if {
	result_value := {"keys": {"abcdef0123456789": "1"}, "ignored": true}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {{
		"code": "rpm_signature.result_format",
		"msg": "Task result has unexpected format: keys.abcdef0123456789: Invalid type. Expected: integer, given: string",
	}}
	lib.assert_equal_results(rpm_signature.deny, expected) with input.attestations as attestations
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
			"code": "rpm_signature.rule_data_provided",
			"msg": "Unexpected format of signing key '\\x01'",
			"severity": "failure",
		},
		{
			"code": "rpm_signature.rule_data_provided",
			"msg": "Rule data has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(rpm_signature.deny, expected) with data.rule_data as d
}

test_rule_data_not_provided if {
	expected := {{
		"code": "rpm_signature.rule_data_provided",
		"msg": "Rule data has unexpected format: (Root): Array must have at least 1 items",
		"severity": "failure",
	}}

	lib.assert_equal_results(rpm_signature.deny, expected) with data.rule_data as {}
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
