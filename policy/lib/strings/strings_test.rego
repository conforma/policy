package lib.strings_test

import rego.v1

import data.lib.assertions

import data.lib.strings as string_utils

test_quoted_values_string if {
	assertions.assert_equal("'a', 'b', 'c'", string_utils.quoted_values_string(["a", "b", "c"]))
	assertions.assert_equal("'a', 'b', 'c'", string_utils.quoted_values_string({"a", "b", "c"}))
}

test_pluralize_maybe if {
	test_cases := [
		{
			"singular": "mouse",
			"plural": "mice",
			"expected": ["mouse", "mice", "mice"],
		},
		{
			"singular": "bug",
			"plural": "",
			"expected": ["bug", "bugs", "bugs"],
		},
	]

	every t in test_cases {
		result := [string_utils.pluralize_maybe(s, t.singular, t.plural) | some s in [{"a"}, {"a", "b"}, {}]]
		assertions.assert_equal(t.expected, result)
	}
}
