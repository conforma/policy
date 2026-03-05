package lib.utils_test

import rego.v1

import data.lib.utils
import data.lib

my_list := ["a", "b", "c"]

my_set := {"a", "b", "c"}

test_to_set if {
	utils.assert_equal(my_set, utils.to_set(my_list))
	utils.assert_equal(my_set, utils.to_set(my_set))
}

test_to_array if {
	utils.assert_equal(my_list, utils.to_array(my_set))
	utils.assert_equal(my_list, utils.to_array(my_list))
}

test_included_in if {
	utils.included_in("a", my_list)
	utils.included_in("a", my_set)
	not utils.included_in("z", my_list)
	not utils.included_in("z", my_set)
}

test_any_included_in if {
	utils.any_included_in(["a", "z"], my_list)
	utils.any_included_in(["a", "z"], my_set)
	utils.any_included_in({"a", "z"}, my_list)
	utils.any_included_in({"a", "z"}, my_set)

	not utils.any_included_in({"x", "z"}, my_set)
}

test_all_included_in if {
	utils.all_included_in({"a", "b"}, my_set)
	not utils.all_included_in({"a", "z"}, my_set)
}

test_none_included_in if {
	utils.none_included_in({"x", "z"}, my_set)
	not utils.none_included_in({"a", "z"}, my_set)
}

test_any_not_included_in if {
	utils.any_not_included_in({"a", "z"}, my_set)
	not utils.any_not_included_in({"a", "b"}, my_set)
}
