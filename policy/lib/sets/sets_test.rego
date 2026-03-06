package lib.sets_test

import rego.v1

import data.lib
import data.lib.assertions
import data.lib.sets

my_list := ["a", "b", "c"]

my_set := {"a", "b", "c"}

test_to_set if {
	assertions.assert_equal(my_set, sets.to_set(my_list))
	assertions.assert_equal(my_set, sets.to_set(my_set))
}

test_to_array if {
	assertions.assert_equal(my_list, sets.to_array(my_set))
	assertions.assert_equal(my_list, sets.to_array(my_list))
}

test_included_in if {
	sets.included_in("a", my_list)
	sets.included_in("a", my_set)
	not sets.included_in("z", my_list)
	not sets.included_in("z", my_set)
}

test_any_included_in if {
	sets.any_included_in(["a", "z"], my_list)
	sets.any_included_in(["a", "z"], my_set)
	sets.any_included_in({"a", "z"}, my_list)
	sets.any_included_in({"a", "z"}, my_set)

	not sets.any_included_in({"x", "z"}, my_set)
}

test_all_included_in if {
	sets.all_included_in({"a", "b"}, my_set)
	not sets.all_included_in({"a", "z"}, my_set)
}

test_none_included_in if {
	sets.none_included_in({"x", "z"}, my_set)
	not sets.none_included_in({"a", "z"}, my_set)
}

test_any_not_included_in if {
	sets.any_not_included_in({"a", "z"}, my_set)
	not sets.any_not_included_in({"a", "b"}, my_set)
}
