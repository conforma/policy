package trusted_artifacts_test

import rego.v1

import data.lib.utils as lib
import data.trusted_artifacts

test_all_good if {
	lib.assert_empty(trusted_artifacts.deny) with input as _task
}

test_bad_ta_param if {
	expected := {{
		"code": "trusted_artifacts.parameter",
		"msg": "The parameter \"I3_ARTIFACTO\" of the Task \"spam-oci-ta/0.1\" does not use the _ARTIFACT suffix",
	}}
	lib.assert_equal_results(trusted_artifacts.deny, expected) with input as _task_bad_ta_param
}

test_bad_ta_result if {
	expected := {{
		"code": "trusted_artifacts.result",
		"msg": "The result \"O3_ARTIFACTO\" of the Task \"spam-oci-ta/0.1\" does not use the _ARTIFACT suffix",
	}}
	lib.assert_equal_results(trusted_artifacts.deny, expected) with input as _task_bad_ta_result
}

test_ignore_non_ta_tasks if {
	task_not_ta_param := json.patch(
		_task_bad_ta_param,
		[{"op": "add", "path": "/spec/steps/0/image", "value": "registry.local/spam:1.0"}],
	)
	lib.assert_empty(trusted_artifacts.deny) with input as task_not_ta_param

	task_not_ta_result := json.patch(
		_task_bad_ta_result,
		[{"op": "add", "path": "/spec/steps/2/image", "value": "registry.local/spam:1.0"}],
	)
	lib.assert_empty(trusted_artifacts.deny) with input as task_not_ta_result
}

test_workspaces if {
	add_workspace := {"op": "add", "path": "/spec/workspaces", "value": [{"name": "spam"}]}
	ta_task_with_workspace := json.patch(_task, [add_workspace])
	expected := {{
		"code": "trusted_artifacts.workspace",
		"msg": "General purpose workspace \"spam\" is not allowed",
	}}
	lib.assert_equal_results(trusted_artifacts.deny, expected) with input as ta_task_with_workspace

	lib.assert_empty(trusted_artifacts.deny) with input as ta_task_with_workspace
		with data.rule_data.allowed_trusted_artifacts_workspaces as ["spam"]

	lib.assert_empty(trusted_artifacts.deny) with input as _non_ta_task
	lib.assert_empty(trusted_artifacts.deny) with input as json.patch(_non_ta_task, [add_workspace])
}

_task := {
	"apiVersion": "tekton.dev/v1",
	"kind": "Task",
	"metadata": {
		"labels": {"app.kubernetes.io/version": "0.1"},
		"name": "spam-oci-ta",
	},
	"spec": {
		"params": [
			{"name": "input"},
			{"name": "ociStorage"},
			{"name": "I1_ARTIFACT"},
			{"name": "I2_ARTIFACT"},
		],
		"results": [
			{"name": "TEST_OUTPUT"},
			{"name": "O1_ARTIFACT"},
			{"name": "O2_ARTIFACT"},
		],
		"steps": [
			{
				"image": "quay.io/redhat-appstudio/build-trusted-artifacts:latest",
				"name": "use-trusted-artifact",
				"args": [
					"use",
					"$(params.I1_ARTIFACT)=/var/workdir/input1",
					"$(params.I2_ARTIFACT)=/var/workdir/input2",
				],
			},
			{
				"image": "registry.local/sleeper:latest",
				"name": "sleep",
				"script": "sleep 5",
			},
			{
				"image": "quay.io/redhat-appstudio/build-trusted-artifacts:latest",
				"name": "create-trusted-artifact",
				"args": [
					"create",
					"--store",
					"$(params.ociStorage)",
					"$(results.O1_ARTIFACT.path)=/var/workdir/output1",
					"$(results.O2_ARTIFACT.path)=/var/workdir/output2",
				],
			},
		],
	},
}

_task_bad_ta_param := json.patch(_task, [
	{"op": "add", "path": "/spec/params/-", "value": {"name": "I3_ARTIFACTO"}},
	{"op": "add", "path": "/spec/steps/0/args/-", "value": "$(params.I3_ARTIFACTO)=/var/workdir/input3"},
])

_task_bad_ta_result := json.patch(_task, [
	{"op": "add", "path": "/spec/results/-", "value": {"name": "O3_ARTIFACTO"}},
	{"op": "add", "path": "/spec/steps/2/args/-", "value": "$(results.O3_ARTIFACTO.path)=/var/workdir/output3"},
])

_non_ta_task := {
	"apiVersion": "tekton.dev/v1",
	"kind": "Task",
	"metadata": {
		"labels": {"app.kubernetes.io/version": "0.1"},
		"name": "spam",
	},
	"spec": {
		"params": [
			{"name": "input"},
			{"name": "ociStorage"},
		],
		"results": [{"name": "TEST_OUTPUT"}],
		"steps": [{
			"image": "registry.local/sleeper:latest",
			"name": "sleep",
			"script": "sleep 5",
		}],
	},
}
