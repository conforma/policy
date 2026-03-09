package slsa_provenance_available_test

import rego.v1

import data.lib
import data.lib.assertions
import data.slsa_provenance_available

test_expected_predicate_type if {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])
	assertions.assert_empty(slsa_provenance_available.deny) with input.attestations as attestations
}

test_att_predicate_type if {
	attestations := _mock_attestations(["spam"])
	expected_deny := {{
		"code": "slsa_provenance_available.attestation_predicate_type_accepted",
		"msg": "Attestation predicate type \"spam\" is not an expected type (https://slsa.dev/provenance/v0.2, https://slsa.dev/provenance/v1)", # regal ignore:line-length
	}}
	assertions.assert_equal_results(slsa_provenance_available.deny, expected_deny) with input.attestations as attestations
}

test_rule_data_format if {
	d := {"allowed_predicate_types": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

	expected := {
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided",
			"msg": "Rule data allowed_predicate_types has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided",
			"msg": "Rule data allowed_predicate_types has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(slsa_provenance_available.deny, expected) with data.rule_data as d
		with input.attestations as _mock_attestations("foo")
}

_mock_attestations(types) := [attestation |
	some type in types
	attestation := {"statement": {
		"predicateType": type,
		"predicate": {"buildType": lib.tekton_pipeline_run},
	}}
]
