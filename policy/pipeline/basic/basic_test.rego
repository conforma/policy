package basic_test

import rego.v1

import data.lib.assertions

import data.basic

test_unexpected_kind if {
	assertions.assert_equal_results(basic.deny, {{
		"code": "basic.expected_kind",
		"msg": "Unexpected kind 'Foo' for pipeline definition",
	}}) with input.kind as "Foo"
}

test_expected_kind if {
	assertions.assert_empty(basic.deny) with input as {
		"apiVersion": "tekton.dev/v1",
		"kind": "Pipeline",
		"spec": {"tasks": []},
	}
}

# A Pipeline-shaped input with the `kind` key entirely removed must still be
# rejected instead of silently passing.
test_missing_kind if {
	assertions.assert_equal_results(basic.deny, {{
		"code": "basic.expected_kind",
		"msg": "Unexpected kind '' for pipeline definition",
	}}) with input as {
		"apiVersion": "tekton.dev/v1",
		"spec": {"tasks": []},
	}
}
