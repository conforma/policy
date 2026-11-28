package step_images_test

import rego.v1

import data.lib.assertions

import data.step_images

test_looks_at_tasks_only if {
	pipeline := {
		"apiVersion": "tekton.dev/v1", "kind": "Pipeline",
		"spec": {"steps": [{"image": "registry.io/repository/not_ok"}]},
	}

	assertions.assert_empty(_legacy_denies) with input as pipeline
}

test_task_with_no_steps if {
	task := {"kind": "Task"}

	assertions.assert_empty(_legacy_denies) with input as task
}

test_task_with_valid_steps if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"spec": {"steps": [
			{"image": "registry.io/repository/ok:1"},
			{"image": "registry.io/repository/ok:2"},
			{"image": "registry.io/repository/ok:3"},
		]},
	}

	assertions.assert_empty(_legacy_denies) with input as task with ec.oci.image_manifest as mock_image_manifest
}

test_task_with_invalid_steps if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
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

	assertions.assert_equal_results(expected, _legacy_denies) with input as task
		with ec.oci.image_manifest as mock_image_manifest
}

mock_image_manifest(ref) := m if {
	startswith(ref, "registry.io/repository/ok")
	m := {}
}

# Preserve the legacy contract during the v2 migration window.
_legacy_denies contains result if {
	some result in step_images.deny
	not endswith(result.code, "_v2")
}

# G17 / RA05-TASK-IMAGE-MISSING-001: only the selected step's image changes.
test_task_image_missing_v2 if {
	task := {"apiVersion": "tekton.dev/v1", "kind": "Task", "spec": {"steps": [{"image": "registry.io/repository/ok:1"}]}}
	assertions.assert_empty(step_images.deny) with input as task with ec.oci.image_manifest as mock_image_manifest
	missing := json.remove(task, ["spec/steps/0/image"])
	results := step_images.deny with input as missing with ec.oci.image_manifest as mock_image_manifest
	assertions.assert_equal({r.code | some r in results}, {"step_images.step_images_accessible_v2"})
	some result in results
	result.term == "noname/noversion"
	result.effective_on == "2027-01-11T00:00:00Z"

	adverse := json.patch(task, [{"op": "replace", "path": "/spec/steps/0/image", "value": "registry.io/repository/not_ok:1"}])
	adverse_results := step_images.deny with input as adverse with ec.oci.image_manifest as mock_image_manifest
	"step_images.step_images_accessible_v2" in {r.code | some r in adverse_results}
}

test_task_image_wrong_type_v2 if {
	every value in [null, 1, true, {}, [], "", " "] {
		task := {"apiVersion": "tekton.dev/v1", "kind": "Task", "spec": {"steps": [{"image": value}]}}
		results := step_images.deny with input as task with ec.oci.image_manifest as mock_image_manifest
		"step_images.step_images_accessible_v2" in {r.code | some r in results}
	}
}

test_task_image_no_steps_v2 if {
	assertions.assert_empty(step_images.deny) with input as {"apiVersion": "tekton.dev/v1", "kind": "Pipeline", "spec": {"steps": [{}]}} with ec.oci.image_manifest as mock_image_manifest
	every spec in [{}, {"steps": []}] {
		task := {"apiVersion": "tekton.dev/v1", "kind": "Task", "spec": spec}
		assertions.assert_empty(step_images.deny) with input as task with ec.oci.image_manifest as mock_image_manifest
	}
}
