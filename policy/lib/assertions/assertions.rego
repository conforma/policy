package lib.assertions

import rego.v1

# Produce more useful output when a test fails

# Beware: `lib.assert_equal(<boolean>, ...)` does not work like
# you would expect, so it's better not to use this for booleans
#
assert_equal(left_value, right_value) if {
	not _assert_equal_fails(left_value, right_value)
}

_assert_equal_fails(left_value, right_value) if {
	left_value != right_value
	_assert_output_two_values("equal", left_value, right_value)
}

assert_not_equal(left_value, right_value) if {
	not _assert_not_equal_fails(left_value, right_value)
}

_assert_not_equal_fails(left_value, right_value) if {
	left_value == right_value
	_assert_output_two_values("not equal", left_value, right_value)
}

assert_empty(value) if {
	not _assert_empty_fails(value)
}

_assert_empty_fails(value) if {
	count(value) > 0
	_assert_output_one_value("empty", value)
}

assert_not_empty(value) if {
	not _assert_not_empty_fails(value)
}

_assert_not_empty_fails(value) if {
	count(value) == 0
	_assert_output_one_value("not empty", value)
}

_assert_output_two_values(assert_type, left_value, right_value) if {
	debug_output := sprintf("Assert %s failure:\n  Left value:  %s\n  Right value: %s", [
		assert_type,
		left_value, right_value,
	])

	# Use trace to show debug output in query explanations and print for stdout
	# regal ignore:print-or-trace-call
	trace(debug_output)

	# regal ignore:print-or-trace-call
	print(debug_output)
}

_assert_output_one_value(assert_type, value) if {
	debug_output := sprintf("Assert %s failure:\n  Value: %s", [assert_type, value])

	# regal ignore:print-or-trace-call
	trace(debug_output)

	# regal ignore:print-or-trace-call
	print(debug_output)
}

# assert_equal_results is successful if both results match.
# The values of "collections" and "effective_on" attributes are ignored.
assert_equal_results(left_result, right_result) if {
	ignore_paths := ["/collections", "/effective_on"]
	assert_equal(
		_ignore_attributes(left_result, ignore_paths),
		_ignore_attributes(right_result, ignore_paths),
	)
}

# assert_equal_results_no_collections is successful if both results match.
# The values of "collections" are ignored.
assert_equal_results_no_collections(left_result, right_result) if {
	ignore_paths := ["/collections"]
	assert_equal(
		_ignore_attributes(left_result, ignore_paths),
		_ignore_attributes(right_result, ignore_paths),
	)
}

_ignore_attributes(values, ignore_paths) := new_values if {
	new_values := {new_value |
		some value in values
		new_value := json.remove(value, ignore_paths)
	}
	count(values) == count(new_values)
} else := values
