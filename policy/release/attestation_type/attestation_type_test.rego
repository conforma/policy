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
	assertions.assert_empty(_legacy_denies) with input.attestations as mock_data(good_type)
	assertions.assert_empty(_legacy_denies) with input.attestations as mock_data(good_type_v1)
}

test_deny_when_not_permitted if {
	expected_msg := sprintf("Unknown attestation type '%s'", [bad_type])
	assertions.assert_equal_results(_legacy_denies, {{
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
	assertions.assert_equal_results(_legacy_denies, expected) with input.attestations as attestations
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
	assertions.assert_equal_results(_legacy_denies, expected) with input.attestations as attestations
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
	}

	assertions.assert_equal_results(_legacy_denies, expected) with data.rule_data as d
		with input.attestations as mock_data("foo")
}

# Preserve the legacy contract during the v2 migration window.
_legacy_denies contains result if {
	some result in attestation_type.deny
	not endswith(result.code, "_v2")
}

# G19 / RA06-ATTESTATION-TYPE-MISSING-001: removing _type must not
# remove an otherwise selected v0.2 PipelineRun from the type check.
test_selected_attestation_missing_type_v2 if {
	baseline := mock_data(good_type)
	assertions.assert_empty(attestation_type.deny) with input.attestations as baseline
	missing := json.remove(baseline[0], ["statement/_type"])
	results := attestation_type.deny with input.attestations as [missing]
	assertions.assert_equal({r.code | some r in results}, {"attestation_type.known_attestation_type_v2"})
	some result in results
	result.effective_on == "2027-01-11T00:00:00Z"
}

test_selected_attestation_wrong_type_v2 if {
	every value in [null, {}, [], 1, true, "", bad_type] {
		results := attestation_type.deny with input.attestations as mock_data(value)
		assertions.assert_equal({r.code | some r in results}, {"attestation_type.known_attestation_type", "attestation_type.known_attestation_type_v2"})
	}
}

test_attestation_type_v2_valid_formats if {
	statements := [
		{"_type": good_type, "predicate": {"buildType": lib.tekton_pipeline_run}},
		{"_type": good_type_v1, "predicateType": "https://slsa.dev/provenance/v1", "predicate": {"buildDefinition": {"buildType": "https://tekton.dev/chains/v2/slsa-tekton"}}},
	]
	every statement in statements {
		assertions.assert_empty(attestation_type.deny) with input.attestations as [{"statement": statement}]
	}
	results := attestation_type.deny with input.attestations as []
	assertions.assert_equal({r.code | some r in results}, {"attestation_type.pipelinerun_attestation_found"})
}
