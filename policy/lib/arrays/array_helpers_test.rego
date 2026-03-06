package lib.arrays_test

import rego.v1

import data.lib.assertions
import data.lib.arrays

ary := [{"x": 1, "z": "X"}, {"x": 2}, {"x": 6, "y": "B"}, {"x": 1, "z": "X"}, {"x": -1}]

test_rank if {
	assertions.assert_equal(4, arrays.rank({"x": 4, "y": "A"}, "x", ary))
	assertions.assert_equal(1, arrays.rank({"x": -1}, "x", ary))
	assertions.assert_equal(0, arrays.rank({"x": -2}, "x", ary))
	assertions.assert_equal(5, arrays.rank({"x": 7}, "x", ary))
	assertions.assert_equal(count(ary), arrays.rank({}, "x", ary))
	assertions.assert_equal(count(ary), arrays.rank({}, "w", ary))
}

test_sort_by if {
	assertions.assert_equal(
		[
			{"x": -1},
			{"x": 1, "z": "X"}, {"x": 1, "z": "X"}, {"x": 2}, {"x": 6, "y": "B"},
		],
		arrays.sort_by("x", ary),
	)
	assertions.assert_equal(
		[
			{"x": 6, "y": "B"},
			{"x": 1, "z": "X"}, {"x": 2}, {"x": 1, "z": "X"}, {"x": -1},
		],
		arrays.sort_by("y", ary),
	)
}

test_sort_by_mixed_types if {
	assertions.assert_equal([{"x": 0}, {"x": "1"}, {"x": 2.0}], arrays.sort_by("x", [{"x": "1"}, {"x": 0}, {"x": 2.0}]))
}

test_le if {
	arrays.le(0, 0)
	arrays.le("A", "A")
	arrays.le(1, "1")
	arrays.le("2", 2)
	arrays.le(3.0, 3.0)
	arrays.le("4.0", 4.0)
	arrays.le(5.0, "5.0")

	arrays.le(0, 1)
	arrays.le("A", "B")
	arrays.le("0", 1)
	arrays.le(0, "1")

	not arrays.le(1, 0)
	not arrays.le("B", "A")
	not arrays.le(1, "0")
	not arrays.le("1", 0)
}
