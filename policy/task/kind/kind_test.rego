package kind_test

import rego.v1

import data.lib.assertions

import data.kind

test_unexpected_kind if {
	assertions.assert_equal_results(kind.deny, {{
		"code": "kind.expected_kind",
		"msg": "Unexpected kind 'Foo' for task definition",
	}}) with input as {"apiVersion": "tekton.dev/v1", "kind": "Foo"}
}

test_expected_kind if {
	assertions.assert_empty(kind.deny) with input as {"apiVersion": "tekton.dev/v1", "kind": "Task"}
}

test_kind_not_found if {
	assertions.assert_equal_results(kind.deny, {{
		"code": "kind.kind_present",
		"msg": "Required field 'kind' not found",
	}}) with input as {"apiVersion": "tekton.dev/v1", "bad": "Foo"}
}

test_skipped_without_api_version if {
	assertions.assert_empty(kind.deny) with input as {"image": {"ref": "example.com/img"}}
		with ec.oci.image_manifest as null
}

test_task_bundle_wrong_kind if {
	_manifest := {"layers": [{
		"digest": "sha256:abc",
		"annotations": {
			"dev.tekton.image.kind": "task",
			"dev.tekton.image.name": "my-task",
			"dev.tekton.image.apiVersion": "v1",
		},
	}]}
	_task := {"apiVersion": "tekton.dev/v1", "kind": "Pipeline"}

	assertions.assert_equal_results(kind.deny, {{
		"code": "kind.expected_kind",
		"msg": "Unexpected kind 'Pipeline' for task definition",
	}}) with input.image.ref as "registry.example.com/bundle@sha256:aaa"
		with ec.oci.image_manifest as _manifest
		with ec.oci.blob_files as {"my-task": _task}
}
