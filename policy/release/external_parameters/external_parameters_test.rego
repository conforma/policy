package external_parameters_test

import rego.v1

import data.external_parameters

import data.lib.assertions

test_success if {
	assertions.assert_empty(external_parameters.deny) with input.attestations as [good_provenance]
}

test_pipeline_run_params_missing_params if {
	# regal ignore:line-length
	provenance := json.remove(good_provenance, ["/statement/predicate/buildDefinition/externalParameters/runSpec/params/0"])
	expected := {{
		"code": "external_parameters.pipeline_run_params",
		# regal ignore:line-length
		"msg": `PipelineRun params, {"git-revision", "output-image"}, do not match expectation, {"git-repo", "git-revision", "output-image"}.`,
	}}
	assertions.assert_equal_results(external_parameters.deny, expected) with input.attestations as [provenance]
}

test_pipeline_run_params_empty_values if {
	provenance := json.patch(good_provenance, [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/externalParameters/runSpec/params/0/value",
		"value": "",
	}])
	expected := {{
		"code": "external_parameters.pipeline_run_params",
		# regal ignore:line-length
		"msg": `PipelineRun params, {"git-revision", "output-image"}, do not match expectation, {"git-repo", "git-revision", "output-image"}.`,
	}}
	assertions.assert_equal_results(external_parameters.deny, expected) with input.attestations as [provenance]
}

test_restrict_shared_volumes_existing_pvc if {
	provenance := json.patch(good_provenance, [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/externalParameters/runSpec/workspaces/0",
		"value": {"persistentVolumeClaim": {"claimName": "my-pvc"}},
	}])
	expected := {{
		"code": "external_parameters.restrict_shared_volumes",
		"msg": "PipelineRun uses shared volumes, {{\"persistentVolumeClaim\": {\"claimName\": \"my-pvc\"}}}.",
	}}
	assertions.assert_equal_results(external_parameters.deny, expected) with input.attestations as [provenance]
}

test_rule_data_validation if {
	d := {"pipeline_run_params": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

	expected := {
		{
			"code": "external_parameters.pipeline_run_params_provided",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "external_parameters.pipeline_run_params_provided",
			"msg": "Rule data pipeline_run_params has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	provenance := json.patch(good_provenance, [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/externalParameters/runSpec/params",
		"value": [{"name": 1, "value": "one"}, {"name": "foo", "value": "oof"}],
	}])
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data as d
		with input.attestations as [provenance]
}

good_provenance := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa",
		"externalParameters": {"runSpec": {
			"pipelineSpec": {},
			"params": [
				{"name": "git-repo", "value": "some-git-repo"},
				{"name": "git-revision", "value": "some-git-revision"},
				{"name": "output-image", "value": "some-output-image"},
			],
			"workspaces": [{"volumeClaimTemplate": {"spec": {}}}],
		}},
	}},
}}
