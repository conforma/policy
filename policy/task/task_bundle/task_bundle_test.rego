package task_bundle_test

import rego.v1

import data.lib.assertions

import data.task_bundle

# Mock manifest with Tekton task layers
_mock_manifest := {"layers": [
	{
		"digest": "sha256:abc123",
		"annotations": {
			"dev.tekton.image.kind": "task",
			"dev.tekton.image.name": "my-task",
			"dev.tekton.image.apiVersion": "v1",
		},
	},
	{
		"digest": "sha256:def456",
		"annotations": {
			"dev.tekton.image.kind": "task",
			"dev.tekton.image.name": "other-task",
			"dev.tekton.image.apiVersion": "v1",
		},
	},
]}

# A valid task definition
_good_task := {
	"apiVersion": "tekton.dev/v1",
	"kind": "Task",
	"metadata": {"name": "my-task"},
	"spec": {"steps": [{"name": "echo", "image": "alpine:latest"}]},
}

# A task with wrong kind
_bad_kind_task := {
	"apiVersion": "tekton.dev/v1",
	"kind": "Pipeline",
	"metadata": {"name": "bad-kind-task"},
	"spec": {"steps": [{"name": "echo", "image": "alpine:latest"}]},
}

# A task with a step missing image (and no ref)
_missing_image_task := {
	"apiVersion": "tekton.dev/v1",
	"kind": "Task",
	"metadata": {"name": "missing-image-task"},
	"spec": {"steps": [{"name": "no-image", "script": "echo hello"}]},
}

# Non-task-bundle input (regular container image)
test_non_task_bundle if {
	assertions.assert_empty(task_bundle.warn) with input.image.ref as "registry.example.com/image@sha256:abc"
		with ec.oci.image_manifest as null

	assertions.assert_empty(task_bundle.deny) with input.image.ref as "registry.example.com/image@sha256:abc"
		with ec.oci.image_manifest as null
}

# Task bundle detection
test_task_bundle_detected if {
	assertions.assert_equal_results(task_bundle.warn, {{
		"code": "task_bundle.detected",
		"msg": "Detected task bundle with 1 task(s) extracted",
	}}) with input.image.ref as "registry.example.com/bundle@sha256:aaa"
		with ec.oci.image_manifest as _mock_manifest
		with ec.oci.blob_files as {"my-task": _good_task}
}

# Delegation to kind policy: wrong kind triggers deny with prefixed code
test_delegation_kind_deny if {
	lib_result := task_bundle.deny with input.image.ref as "registry.example.com/bundle@sha256:aaa"
		with ec.oci.image_manifest as _mock_manifest
		with ec.oci.blob_files as {"my-task": _bad_kind_task}

	some result in lib_result
	result.code == "task_bundle.kind.expected_kind"
	contains(result.msg, "[bad-kind-task]")
}

# No tasks extracted
test_no_tasks_extracted if {
	assertions.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.no_tasks",
		"msg": "Task bundle detected but no tasks could be extracted from registry.example.com/bundle@sha256:aaa",
	}}) with input.image.ref as "registry.example.com/bundle@sha256:aaa"
		with ec.oci.image_manifest as _mock_manifest
		with ec.oci.blob_files as {}
}
