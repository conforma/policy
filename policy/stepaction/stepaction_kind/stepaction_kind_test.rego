package stepaction_kind_test

import rego.v1

import data.lib.assertions

import data.stepaction_kind as kind

test_invalid_kind if {
	assertions.assert_equal_results(kind.deny, {{
		"code": "stepaction_kind.valid",
		"msg": `Unexpected kind "Foo" for StepAction definition`,
	}}) with input.kind as "Foo"
}

test_valid_kind if {
	assertions.assert_empty(kind.deny) with input as {"kind": "StepAction"}
}
