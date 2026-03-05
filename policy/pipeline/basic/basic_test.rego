package basic_test

import rego.v1

import data.basic
import data.lib.utils as lib

test_unexpected_kind if {
	lib.assert_equal_results(basic.deny, {{
		"code": "basic.expected_kind",
		"msg": "Unexpected kind 'Foo' for pipeline definition",
	}}) with input.kind as "Foo"
}
