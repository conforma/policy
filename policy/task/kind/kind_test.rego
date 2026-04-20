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
}
