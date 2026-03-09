package step_images_test

import rego.v1

import data.lib.assertions

import data.step_images

test_looks_at_tasks_only if {
	pipeline := {
		"kind": "Pipeline",
		"spec": {"steps": [{"image": "registry.io/repository/not_ok"}]},
	}

	assertions.assert_empty(step_images.deny) with input as pipeline
}

test_task_with_no_steps if {
	task := {"kind": "Task"}

	assertions.assert_empty(step_images.deny) with input as task
}

test_task_with_valid_steps if {
	task := {
		"kind": "Task",
		"spec": {"steps": [
			{"image": "registry.io/repository/ok:1"},
			{"image": "registry.io/repository/ok:2"},
			{"image": "registry.io/repository/ok:3"},
		]},
	}

	assertions.assert_empty(step_images.deny) with input as task with ec.oci.image_manifest as mock_image_manifest
}

test_task_with_invalid_steps if {
	task := {
		"kind": "Task",
		"spec": {"steps": [
			{"image": "registry.io/repository/ok:1"},
			{"image": "registry.io/repository/not_ok:2"},
			{"image": "registry.io/repository/ok:3"},
			{"image": "registry.io/repository/not_ok:4"},
			{"image": "registry.io/repository/ok:5"},
		]},
	}

	expected := {
		{
			"code": "step_images.step_images_accessible",
			"msg": "Step 1 uses inaccessible image ref 'registry.io/repository/not_ok:2'",
			"term": "registry.io/repository/not_ok:2",
		},
		{
			"code": "step_images.step_images_accessible",
			"msg": "Step 3 uses inaccessible image ref 'registry.io/repository/not_ok:4'",
			"term": "registry.io/repository/not_ok:4",
		},
	}

	assertions.assert_equal_results(expected, step_images.deny) with input as task
		with ec.oci.image_manifest as mock_image_manifest
}

mock_image_manifest(ref) := m if {
	startswith(ref, "registry.io/repository/ok")
	m := {}
}
