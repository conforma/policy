package lib.utils_test

import rego.v1

import data.lib.utils
import data.lib

test_quoted_values_string if {
	utils.assert_equal("'a', 'b', 'c'", utils.quoted_values_string(["a", "b", "c"]))
	utils.assert_equal("'a', 'b', 'c'", utils.quoted_values_string({"a", "b", "c"}))
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
		result := [utils.pluralize_maybe(s, t.singular, t.plural) | some s in [{"a"}, {"a", "b"}, {}]]
		utils.assert_equal(t.expected, result)
	}
}
