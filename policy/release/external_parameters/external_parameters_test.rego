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
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
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

# RA10-EXTERNAL-RULE-DATA-SCALAR-001: a present but scalar `pipeline_run_params` value must
# produce a format rejection from the v2 rule instead of silently skipping the check. The
# legacy pipeline_run_params_provided is untouched: a builtin error in its schema validation
# still suppresses its result, which is the gap the v2 rule closes. The consumer rule keeps
# its current behavior and compares the params against an empty expectation.
test_pipeline_run_params_provided_v2_scalar_rejected if {
	consumer_mismatch := {
		"code": "external_parameters.pipeline_run_params",
		# regal ignore:line-length
		"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, set().`,
	}

	expected_number := {
		consumer_mismatch,
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Invalid type. Expected: array, given: integer",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected_number) with data.rule_data as {"pipeline_run_params": 1}
		with input.attestations as [good_provenance]

	expected_string := {
		consumer_mismatch,
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected_string) with data.rule_data as {"pipeline_run_params": "x"}
		with input.attestations as [good_provenance]

	expected_boolean := {
		consumer_mismatch,
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Invalid type. Expected: array, given: boolean",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected_boolean) with data.rule_data as {"pipeline_run_params": true}
		with input.attestations as [good_provenance]
}

# A string containing JSON text for an array must not be mistaken for a
# native array: the legacy rule parses it as an empty array and reports only
# the container-level minItems diagnostic, while the v2 rule reports the
# actual string type.
test_pipeline_run_params_provided_v2_json_text_string_rejected if {
	expected := {
		{
			"code": "external_parameters.pipeline_run_params",
			# regal ignore:line-length
			"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, set().`,
		},
		{
			"code": "external_parameters.pipeline_run_params_provided",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data as {"pipeline_run_params": "[]"}
		with input.attestations as [good_provenance]
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_pipeline_run_params_provided_v2_precedence if {
	expected := {
		{
			"code": "external_parameters.pipeline_run_params",
			# regal ignore:line-length
			"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, set().`,
		},
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Invalid type. Expected: array, given: integer",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data_custom as {"pipeline_run_params": 1}
		with data.rule_data as {"pipeline_run_params": ["git-repo", "git-revision", "output-image"]}
		with input.attestations as [good_provenance]
}

# Shape controls locking in the current format contract: null, wrong-container, explicitly
# empty, and absent values are all rejected by both rules with identical messages. There is
# no default for this key, so an absent key resolves to an empty list.
test_pipeline_run_params_null_rejected if {
	expected := {
		{
			"code": "external_parameters.pipeline_run_params",
			# regal ignore:line-length
			"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, set().`,
		},
		{
			"code": "external_parameters.pipeline_run_params_provided",
			"msg": "Rule data pipeline_run_params has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data as {"pipeline_run_params": null}
		with input.attestations as [good_provenance]
}

test_pipeline_run_params_wrong_container_rejected if {
	expected := {
		{
			"code": "external_parameters.pipeline_run_params",
			# regal ignore:line-length
			"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, set().`,
		},
		{
			"code": "external_parameters.pipeline_run_params_provided",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data as {"pipeline_run_params": {}}
		with input.attestations as [good_provenance]
}

test_pipeline_run_params_empty_array_rejected if {
	expected := {
		{
			"code": "external_parameters.pipeline_run_params",
			# regal ignore:line-length
			"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, set().`,
		},
		{
			"code": "external_parameters.pipeline_run_params_provided",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data as {"pipeline_run_params": []}
		with input.attestations as [good_provenance]
}

test_pipeline_run_params_absent_rejected if {
	expected := {
		{
			"code": "external_parameters.pipeline_run_params",
			# regal ignore:line-length
			"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, set().`,
		},
		{
			"code": "external_parameters.pipeline_run_params_provided",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "external_parameters.pipeline_run_params_provided_v2",
			"msg": "Rule data pipeline_run_params has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data as {}
		with input.attestations as [good_provenance]
}

# Valid data must still reach the consumer rule: a matching expectation passes
# and a nonmatching expectation is reported by pipeline_run_params.
test_pipeline_run_params_consumer_with_custom_data if {
	assertions.assert_empty(external_parameters.deny) with data.rule_data as {"pipeline_run_params": ["git-repo", "git-revision", "output-image"]}
		with input.attestations as [good_provenance]

	expected := {{
		"code": "external_parameters.pipeline_run_params",
		# regal ignore:line-length
		"msg": `PipelineRun params, {"git-repo", "git-revision", "output-image"}, do not match expectation, {"git-repo", "output-image"}.`,
	}}
	assertions.assert_equal_results(external_parameters.deny, expected) with data.rule_data as {"pipeline_run_params": ["git-repo", "output-image"]}
		with input.attestations as [good_provenance]
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
