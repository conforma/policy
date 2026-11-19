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
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided_v2",
			"msg": "Rule data allowed_predicate_types has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided_v2",
			"msg": "Rule data allowed_predicate_types has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(slsa_provenance_available.deny, expected) with data.rule_data as d
		with input.attestations as _mock_attestations("foo")
}

# RA19-PREDICATE-ALLOWLIST-CONSUMER-001: a present but scalar
# allowed_predicate_types value must produce a format rejection from the v2
# rule instead of the consumer result and format result both disappearing.
# The legacy allowed_predicate_types_provided stays silent: a builtin error in
# its schema validation suppresses the result, which is the gap the v2 rule
# closes.
test_rule_data_provided_v2_scalar_rejected if {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])
	expected := {{
		"code": "slsa_provenance_available.allowed_predicate_types_provided_v2",
		"msg": "Rule data allowed_predicate_types has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(slsa_provenance_available.deny, expected) with input.attestations as attestations
		with data.rule_data as {"allowed_predicate_types": 1}
}

# A malformed high-priority override above a valid lower-priority list must
# be rejected rather than silently using the lower-priority value.
test_rule_data_provided_v2_precedence if {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])
	expected := {{
		"code": "slsa_provenance_available.allowed_predicate_types_provided_v2",
		"msg": "Rule data allowed_predicate_types has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(slsa_provenance_available.deny, expected) with input.attestations as attestations
		with data.rule_data_custom as {"allowed_predicate_types": 1}
		with data.rule_data as {"allowed_predicate_types": ["https://slsa.dev/provenance/v0.2"]}
}

# An explicitly empty list is a format rejection, not an intentional disable
# switch: the schema requires a nonempty list. Null, object and string values
# keep producing a format rejection as well, on both rules where the legacy
# schema validation already reported them.
test_rule_data_provided_v2_empty_and_wrong_shapes if {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])

	# An empty list accepts no predicate type, so the consumer mismatch fires
	# alongside the format rejection on both rules.
	empty_expected := {
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided",
			"msg": "Rule data allowed_predicate_types has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided_v2",
			"msg": "Rule data allowed_predicate_types has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "slsa_provenance_available.attestation_predicate_type_accepted",
			"msg": "Attestation predicate type \"https://slsa.dev/provenance/v0.2\" is not an expected type ()",
		},
	}
	assertions.assert_equal_results(slsa_provenance_available.deny, empty_expected) with input.attestations as attestations
		with data.rule_data as {"allowed_predicate_types": []}

	null_expected := {
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided",
			"msg": "Rule data allowed_predicate_types has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
		{
			"code": "slsa_provenance_available.allowed_predicate_types_provided_v2",
			"msg": "Rule data allowed_predicate_types has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(slsa_provenance_available.deny, null_expected) with input.attestations as attestations
		with data.rule_data as {"allowed_predicate_types": null}

	scalar_string_expected := {{
		"code": "slsa_provenance_available.allowed_predicate_types_provided_v2",
		"msg": "Rule data allowed_predicate_types has unexpected format: (Root): Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(slsa_provenance_available.deny, scalar_string_expected) with input.attestations as attestations
		with data.rule_data as {"allowed_predicate_types": "https://slsa.dev/provenance/v0.2"}
}

# Removing the override keeps the lower-priority data effective: with the key
# absent from every configured source, the default v0.2/v1 predicate list
# remains in use and the consumer still works.
test_rule_data_provided_v2_absent_falls_back if {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])
	assertions.assert_empty(slsa_provenance_available.deny) with input.attestations as attestations
		with data.rule_data as {}
}

# The valid matching and nonmatching consumer controls keep working alongside
# the v2 format rule.
test_rule_data_provided_v2_consumer_controls if {
	attestations := _mock_attestations(["https://slsa.dev/provenance/v0.2"])

	assertions.assert_empty(slsa_provenance_available.deny) with input.attestations as attestations
		with data.rule_data as {"allowed_predicate_types": ["https://slsa.dev/provenance/v0.2"]}

	expected := {{
		"code": "slsa_provenance_available.attestation_predicate_type_accepted",
		"msg": "Attestation predicate type \"https://slsa.dev/provenance/v0.2\" is not an expected type (spam)",
	}}
	assertions.assert_equal_results(slsa_provenance_available.deny, expected) with input.attestations as attestations
		with data.rule_data as {"allowed_predicate_types": ["spam"]}
}

_mock_attestations(types) := [attestation |
	some type in types
	attestation := {"statement": {
		"predicateType": type,
		"predicate": {"buildType": lib.tekton_pipeline_run},
	}}
]
