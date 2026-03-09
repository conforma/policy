package slsa_source_version_controlled_test

import rego.v1

import data.lib
import data.lib.assertions
import data.slsa_source_version_controlled

test_all_good if {
	materials := [
		{
			"uri": "git+https://example/repo",
			"digest": {"sha1": "49ef4c1f9273718b2421b2c076f09786ede5982c"},
		},
		{
			"uri": "git+https://exmaple/other-repo.git",
			"digest": {"sha1": "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"},
		},
	]

	assertions.assert_empty(slsa_source_version_controlled.deny) with input.attestations as [_mock_slsa_v02_attestation(materials)] # regal ignore:line-length
	assertions.assert_empty(slsa_source_version_controlled.deny) with input.attestations as [_mock_slsa_v1_attestation(materials)]
}

test_non_git_uri if {
	materials := [
		{
			"uri": "ggit+https://example/repo",
			"digest": {"sha1": "49ef4c1f9273718b2421b2c076f09786ede5982c"},
		},
		{
			"uri": "svn+https://exmaple/other-repo.git",
			"digest": {"sha1": "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"},
		},
	]

	expected := {
		{
			"code": "slsa_source_version_controlled.materials_uri_is_git_repo",
			"msg": "Material URI \"ggit+https://example/repo\" is not a git URI",
		},
		{
			"code": "slsa_source_version_controlled.materials_uri_is_git_repo",
			"msg": "Material URI \"svn+https://exmaple/other-repo.git\" is not a git URI",
		},
	}

	assertions.assert_equal_results(
		expected,
		slsa_source_version_controlled.deny,
	) with input.attestations as [_mock_slsa_v02_attestation(materials)]

	assertions.assert_equal_results(
		expected,
		slsa_source_version_controlled.deny,
	) with input.attestations as [_mock_slsa_v1_attestation(materials)]
}

# regal ignore:rule-length
test_non_git_commit if {
	materials := [
		{
			"uri": "git+https://example/repo",
			# Invalid hexadecimal character "g"
			"digest": {"sha1": "g9ef4c1f9273718b2421b2c076f09786ede5982c"},
		},
		{
			"uri": "git+https://exmaple/other-repo.git",
			# Too short, 39 characters
			"digest": {"sha1": "1d2d2f924e986ac86fdf7b36c94bcdf32beec15"},
		},
		{
			"uri": "git+https://exmaple/yet-another-repo.git",
			# Too long, 41 characters
			"digest": {"sha1": "36d89a3cadcdf269110757df1074b4ef45fe641ee"},
		},
	]

	expected := {
		{
			"code": "slsa_source_version_controlled.materials_include_git_sha",
			"msg": "Material digest \"g9ef4c1f9273718b2421b2c076f09786ede5982c\" is not a git commit sha",
		},
		{
			"code": "slsa_source_version_controlled.materials_include_git_sha",
			"msg": "Material digest \"1d2d2f924e986ac86fdf7b36c94bcdf32beec15\" is not a git commit sha",
		},
		{
			"code": "slsa_source_version_controlled.materials_include_git_sha",
			"msg": "Material digest \"36d89a3cadcdf269110757df1074b4ef45fe641ee\" is not a git commit sha",
		},
	}

	assertions.assert_equal_results(
		expected,
		slsa_source_version_controlled.deny,
	) with input.attestations as [_mock_slsa_v02_attestation(materials)]

	assertions.assert_equal_results(
		expected,
		slsa_source_version_controlled.deny,
	) with input.attestations as [_mock_slsa_v1_attestation(materials)]
}

test_invalid_materials if {
	materials := [
		# Missing uri
		{"digest": {"sha1": "49ef4c1f9273718b2421b2c076f09786ede5982c"}},
		# Missing digest
		{"uri": "git+https://example/repo"},
		# Missing digest.sha1
		{"url": "git+https://example/repo", "digest": {}},
	]

	expected := {{
		"code": "slsa_source_version_controlled.materials_format_okay",
		"msg": "No materials match expected format",
	}}

	assertions.assert_equal_results(
		expected,
		slsa_source_version_controlled.deny,
	) with input.attestations as [_mock_slsa_v02_attestation(materials)]

	assertions.assert_equal_results(
		expected,
		slsa_source_version_controlled.deny,
	) with input.attestations as [_mock_slsa_v1_attestation(materials)]
}

_mock_slsa_v02_attestation(materials) := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"materials": materials,
}}}

_mock_slsa_v1_attestation(materials) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa",
		"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		"resolvedDependencies": materials,
	}},
}}
