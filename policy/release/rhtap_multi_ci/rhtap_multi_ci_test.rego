package rhtap_multi_ci_test

import rego.v1

import data.lib.assertions
import data.rhtap_multi_ci

test_atts_happy_path if {
	assertions.assert_empty(rhtap_multi_ci.deny) with input.attestations as [good_att]
	assertions.assert_empty(rhtap_multi_ci.deny) with input.attestations as [ignored_att, good_att]
}

test_atts_missing if {
	expected := {
		"code": "rhtap_multi_ci.attestation_found",
		"msg": sprintf("%s%s%s%s%s", [
			"A SLSA v1.0 provenance with one of the following RHTAP Multi-CI build types was not found:",
			" 'https://redhat.com/rhtap/slsa-build-types/jenkins-build/v1',",
			" 'https://redhat.com/rhtap/slsa-build-types/github-build/v1',",
			" 'https://redhat.com/rhtap/slsa-build-types/gitlab-build/v1',",
			" 'https://redhat.com/rhtap/slsa-build-types/azure-build/v1'.",
		]),
	}

	assertions.assert_equal_results({expected}, rhtap_multi_ci.deny) with input.attestations as []
	assertions.assert_equal_results({expected}, rhtap_multi_ci.deny) with input.attestations as [ignored_att]
}

test_fields_missing if {
	expected = {
		{
			"code": "rhtap_multi_ci.attestation_format",
			"msg": "RHTAP jenkins attestation problem: runDetails.metadata: invocationID is required",
		},
		{
			"code": "rhtap_multi_ci.attestation_format",
			"msg": "RHTAP jenkins attestation problem: runDetails.builder: id is required",
		},
	}
	assertions.assert_equal_results(expected, rhtap_multi_ci.deny) with input.attestations as [missing_fields_att]
}

# Not very useful except to get 100% coverage
# (I don't feel like repeating the above tests with the other two build types)
test_schema_sanity if {
	assertions.assert_not_equal(rhtap_multi_ci._predicate_schema_base, rhtap_multi_ci._predicate_schema("jenkins"))
	assertions.assert_equal(rhtap_multi_ci._predicate_schema_base, rhtap_multi_ci._predicate_schema("github"))
	assertions.assert_equal(rhtap_multi_ci._predicate_schema_base, rhtap_multi_ci._predicate_schema("gitlab"))
}

good_build_type := "https://redhat.com/rhtap/slsa-build-types/jenkins-build/v1"

good_att := mock_att(good_build_type, {
	"metadata": {"invocationID": "foo"},
	"builder": {"id": "42", "version": {}},
})

missing_fields_att := mock_att(good_build_type, {
	"metadata": {"vacationID": "foo"},
	"builder": {"name": "Bob", "version": {}},
})

ignored_att := mock_att("https://other/build/type/v1", {})

mock_att(build_type, run_details) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {"buildType": build_type},
		"runDetails": run_details,
	},
}}

test_rhtap_build_type if {
	assertions.assert_equal(
		"https://redhat.com/rhtap/slsa-build-types/bacon-build/v1",
		rhtap_multi_ci._build_type("bacon"),
	)
}
