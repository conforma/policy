package lib.tekton_test

import rego.v1

import data.lib.utils
import data.lib
import data.lib.tekton

test_disallowed_task_reference if {
	tasks := [
		{"name": "my-task-1", "taskRef": {}},
		{"name": "my-task-2", "ref": {}},
	]

	expected := utils.to_set(tasks)
	utils.assert_equal(tekton.disallowed_task_reference(tasks), expected)
}

test_empty_task_bundle_reference if {
	tasks := [
		{"name": "my-task-1", "taskRef": {"bundle": ""}},
		{"name": "my-task-2", "ref": {"bundle": ""}},
	]

	expected := utils.to_set(tasks)
	utils.assert_equal(tekton.empty_task_bundle_reference(tasks), expected)
}

test_unpinned_task_bundle if {
	tasks := [
		{
			"name": "my-task-1",
			"taskRef": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5"},
		},
		{
			"name": "my-task-2",
			"ref": {"bundle": "reg.com/repo:903d49a833d22f359bce3d67b15b006e1197bae5"},
		},
	]

	expected := utils.to_set(tasks)
	utils.assert_equal(tekton.unpinned_task_bundle(tasks), expected) with data["task-bundles"] as []
}
