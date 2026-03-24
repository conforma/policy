package results_test

import rego.v1

import data.lib
import data.results

test_all_good if {
	lib.assert_empty(results.deny) with input as _mock_task
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

	lib.assert_empty(results.deny) with input as task_v1
		with data.rule_data as rule_data
	lib.assert_empty(results.deny) with input as task_v2
		with data.rule_data as rule_data
	lib.assert_empty(results.deny) with input as task_v3
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

	lib.assert_equal_results(results.deny, {{
		"code": "results.required",
		"msg": `"MISSING_RESULT" result not found in "task" Task/v1 (all versions)`,
	}}) with input as task_v1
		with data.rule_data as rule_data

	lib.assert_equal_results(results.deny, {{
		"code": "results.required",
		"msg": `"MISSING_RESULT" result not found in "task" Task/v2`,
	}}) with input as task_v2
		with data.rule_data as rule_data
}

test_required_result_defined if {
	expected := {{
		"code": "results.required",
		"msg": `"GRILLED" result not found in "bacon" Task (all versions)`,
	}}

	lib.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.patch(_mock_task, [{
			"op": "add",
			"path": "spec/results",
			"value": [],
		}])

	lib.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.remove(_mock_task, ["spec/results"])

	lib.assert_equal_results(results.deny, expected) with data.rule_data as _rule_data
		with input as json.remove(_mock_task, ["spec/results/0"])
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
			"msg": "Rule data required_task_results has unexpected format: 4.task: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "results.rule_data_provided",
			"msg": "Rule data required_task_results has unexpected format: 5.result: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(results.deny, expected) with input as _mock_task
		with data.rule_data as d
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
