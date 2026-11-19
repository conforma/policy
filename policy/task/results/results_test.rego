package results_test

import rego.v1

import data.lib.assertions

import data.results

test_all_good if {
	assertions.assert_empty(results.deny) with input as _mock_task
		with data.rule_data as _rule_data
}

test_different_versions_different_results_required_all_good if {
	task_v1 = {
		"apiVersion": "tekton.dev/v1",
		"kind": "Task",
		"metadata": {"name": "task"},
		"spec": {"results": [{"name": "ALL_RESULT"}]},
	}

	task_v2 = {
		"apiVersion": "tekton.dev/v1",
		"kind": "Task",
		"metadata": {"name": "task", "labels": {"app.kubernetes.io/version": "2"}},
		"spec": {"results": [{"name": "T2_RESULT"}]},
	}

	task_v3 = {
		"apiVersion": "tekton.dev/v1",
		"kind": "Task",
		"metadata": {"name": "task", "labels": {"app.kubernetes.io/version": "3"}},
		"spec": {"results": [{"name": "ALL_RESULT"}]},
	}

	rule_data = {"required_task_results": [
		{"task": "task", "result": "ALL_RESULT"},
		{"task": "task", "version": "2", "result": "T2_RESULT"},
	]}

	assertions.assert_empty(results.deny) with input as task_v1
		with data.rule_data as rule_data
	assertions.assert_empty(results.deny) with input as task_v2
		with data.rule_data as rule_data
	assertions.assert_empty(results.deny) with input as task_v3
		with data.rule_data as rule_data
}

test_different_versions_different_results_required_missing if {
	task_v1 = {
		"apiVersion": "tekton.dev/v1",
		"kind": "Task",
		"metadata": {"name": "task", "labels": {"app.kubernetes.io/version": "1"}},
		"spec": {"results": [{"name": "T1_RESULT"}]},
	}

	task_v2 = {
		"apiVersion": "tekton.dev/v1",
		"kind": "Task",
		"metadata": {"name": "task", "labels": {"app.kubernetes.io/version": "2"}},
		"spec": {"results": [{"name": "T2_RESULT"}]},
	}

	rule_data = {"required_task_results": [
		{"task": "task", "result": "MISSING_RESULT"},
		{"task": "task", "version": "2", "result": "MISSING_RESULT"},
	]}

	# Well-formed results that are simply missing the required one trip both the
	# legacy rule and its v2 successor.
	assertions.assert_equal_results(results.deny, {
		{
			"code": "results.required",
			"msg": `"MISSING_RESULT" result not found in "task" Task/v1 (all versions)`,
		},
		{
			"code": "results.required_v2",
			"msg": `"MISSING_RESULT" result not found in "task" Task/v1 (all versions)`,
		},
	}) with input as task_v1
		with data.rule_data as rule_data

	assertions.assert_equal_results(results.deny, {
		{
			"code": "results.required",
			"msg": `"MISSING_RESULT" result not found in "task" Task/v2`,
		},
		{
			"code": "results.required_v2",
			"msg": `"MISSING_RESULT" result not found in "task" Task/v2`,
		},
	}) with input as task_v2
		with data.rule_data as rule_data
}

test_required_result_defined if {
	# Well-formed (or absent/null) results that lack the required one trip both the
	# legacy rule and its v2 successor.
	expected := {
		{
			"code": "results.required",
			"msg": `"GRILLED" result not found in "bacon" Task (all versions)`,
		},
		{
			"code": "results.required_v2",
			"msg": `"GRILLED" result not found in "bacon" Task (all versions)`,
		},
	}

	assertions.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.patch(_mock_task, [{
			"op": "add",
			"path": "spec/results",
			"value": [],
		}])

	assertions.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.remove(_mock_task, ["spec/results"])

	assertions.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.remove(_mock_task, ["spec/results/0"])

	# A null spec.results is empty-like for both rules and must still deny on both.
	assertions.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.patch(_mock_task, [{
			"op": "add",
			"path": "spec/results",
			"value": null,
		}])

	# A wrong-container object at spec.results that contains a matching result name
	# masks the missing result from the legacy rule (it iterates the object values
	# and finds a match), so only the v2 rule denies here.
	assertions.assert_equal_results(results.deny, {{
		"code": "results.required_v2",
		"msg": `"GRILLED" result not found in "bacon" Task (all versions)`,
	}}) with data.rule_data as _rule_data
		with input as json.patch(_mock_task, [{
			"op": "add",
			"path": "spec/results",
			"value": {"GRILLED": {"name": "GRILLED"}},
		}])
}

# A Task with no usable metadata.name can never be matched against the rule data, so
# the legacy rule silently passes it. The v2 rule reports it when required results
# are configured.
test_missing_metadata_name if {
	expected := {{
		"code": "results.required_v2",
		"msg": "Task has no usable metadata.name; required results cannot be verified",
	}}

	# metadata present but without a name.
	assertions.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.remove(_mock_task, ["metadata/name"])

	# metadata is not an object at all.
	assertions.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.patch(_mock_task, [{"op": "replace", "path": "metadata", "value": "oops"}])

	# With no required results configured the check stays a no-op.
	assertions.assert_empty(results.deny) with data.rule_data as {"required_task_results": []}
		with input as json.remove(_mock_task, ["metadata/name"])
}

test_rule_data_provided if {
	d := {"required_task_results": [
		# Wrong type
		1,
		# Duplicated items
		{"task": "task1", "result": "result1"},
		{"task": "task1", "result": "result1"},
		# Additional properties
		{"task": "task2", "result": "result2", "foo": "bar"},
		# Bad type for task
		{"task": 3, "result": "result3"},
		# Bad type for result
		{"task": "task4", "result": 4},
	]}

	expected := {
		{
			"code": "results.rule_data_provided",
			"msg": "Rule data required_task_results has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided",
			"msg": "Rule data required_task_results has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided",
			"msg": "Rule data required_task_results has unexpected format: 3: Additional property foo is not allowed",
			"severity": "warning",
		},
		{
			"code": "results.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data required_task_results has unexpected format: 4.task: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data required_task_results has unexpected format: 5.result: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided_v2",
			"msg": "Rule data required_task_results has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided_v2",
			"msg": "Rule data required_task_results has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided_v2",
			"msg": "Rule data required_task_results has unexpected format: 3: Additional property foo is not allowed",
			"severity": "warning",
		},
		{
			"code": "results.rule_data_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data required_task_results has unexpected format: 4.task: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data required_task_results has unexpected format: 5.result: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(results.deny, expected) with input as _mock_task
		with data.rule_data as d
}

# A present but scalar `required_task_results` value must produce a format
# rejection from the v2 rule instead of silently skipping the check. The legacy
# rule_data_provided is untouched: a builtin error in its schema validation
# still suppresses its result, which is the gap rule_data_provided_v2 closes.
test_rule_data_provided_v2_scalar_rejected if {
	expected := {{
		"code": "results.rule_data_provided_v2",
		"msg": "Rule data required_task_results has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(results.deny, expected) with input as _mock_task
		with data.rule_data as {"required_task_results": 3}

	expected_bool := {{
		"code": "results.rule_data_provided_v2",
		"msg": "Rule data required_task_results has unexpected format: (Root): Invalid type. Expected: array, given: boolean",
		"severity": "failure",
	}}
	assertions.assert_equal_results(results.deny, expected_bool) with input as _mock_task
		with data.rule_data as {"required_task_results": true}
}

# A string value is malformed even when it contains JSON text for a valid
# array: JSON text in a scalar must not be mistaken for a native array. A
# native empty array stays an intentional no-op.
test_rule_data_provided_v2_json_text_string_rejected if {
	expected := {{
		"code": "results.rule_data_provided_v2",
		"msg": "Rule data required_task_results has unexpected format: (Root): Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(results.deny, expected) with input as _mock_task
		with data.rule_data as {"required_task_results": "x"}

	assertions.assert_equal_results(results.deny, expected) with input as _mock_task
		with data.rule_data as {"required_task_results": "[]"}

	assertions.assert_empty(results.deny) with input as _mock_task
		with data.rule_data as {"required_task_results": []}
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_rule_data_provided_v2_precedence if {
	expected := {{
		"code": "results.rule_data_provided_v2",
		"msg": "Rule data required_task_results has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(results.deny, expected) with input as _mock_task
		with data.rule_data_custom as {"required_task_results": 3}
		with data.rule_data as {"required_task_results": [{"task": "bacon", "result": "GRILLED"}]}
}

_mock_task := {
	"apiVersion": "tekton.dev/v1",
	"kind": "Task",
	"metadata": {"name": "bacon"},
	"spec": {"results": [
		{"name": "GRILLED"},
		{"name": "SCENT"},
	]},
}

_rule_data := {"required_task_results": [{"task": "bacon", "result": "GRILLED"}]}
