package lib.assertions_test

import rego.v1

import data.lib
import data.lib.assertions

test_assert_equal if {
	assertions.assert_equal("a", "a")
	assertions.assert_equal({"a": 10}, {"a": 10})
	assertions.assert_equal(["a"], ["a"])
	assertions.assert_equal({"a"}, {"a"})
	not assertions.assert_equal("a", "b")
	not assertions.assert_equal({"a": 10}, {"a", 11})
	not assertions.assert_equal(["a"], ["b"])
	not assertions.assert_equal({"a"}, {"b"})
}

test_assert_not_equal if {
	assertions.assert_not_equal("a", "b")
	assertions.assert_not_equal({"a": 10}, {"a", 11})
	assertions.assert_not_equal(["a"], ["b"])
	assertions.assert_not_equal({"a"}, {"b"})
	not assertions.assert_not_equal("a", "a")
	not assertions.assert_not_equal({"a": 10}, {"a": 10})
	not assertions.assert_not_equal(["a"], ["a"])
	not assertions.assert_not_equal({"a"}, {"a"})
}

test_assert_empty if {
	assertions.assert_empty([])
	assertions.assert_empty({})
	assertions.assert_empty(set())
	not assertions.assert_empty(["a"])
	not assertions.assert_empty({"a"})
	not assertions.assert_empty({"a": "b"})
}

test_assert_not_empty if {
	assertions.assert_not_empty(["a"])
	assertions.assert_not_empty({"a"})
	assertions.assert_not_empty({"a": "b"})
	not assertions.assert_not_empty([])
	not assertions.assert_not_empty({})
	not assertions.assert_not_empty(set())
}

# regal ignore:rule-length
test_assert_equal_results if {
	# Empty results
	assertions.assert_equal_results(set(), set())
	assertions.assert_equal_results({{}}, {{}})

	# collections attribute is ignored
	assertions.assert_equal_results({{"collections": ["a", "b"]}}, {{}})
	assertions.assert_equal_results({{}}, {{"collections": ["a", "b"]}})
	assertions.assert_equal_results({{"collections": ["a", "b"]}}, {{"collections": ["c", "d"]}})
	assertions.assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"]}},
		{{"spam": "maps", "collections": ["c", "d"]}},
	)

	# effective_on attribute is ignored
	assertions.assert_equal_results({{"effective_on": "2022-01-01T00:00:00Z"}}, {{}})
	assertions.assert_equal_results({{}}, {{"effective_on": "2022-01-01T00:00:00Z"}})
	assertions.assert_equal_results(
		{{"effective_on": "2022-01-01T00:00:00Z"}},
		{{"effective_on": "1970-01-01T00:00:00Z"}},
	)
	assertions.assert_equal_results(
		{{"spam": "maps", "effective_on": "2022-01-01T00:00:00Z"}},
		{{"spam": "maps", "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# both collections and effective_on attributes are ignored
	assertions.assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"spam": "maps", "collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# any other attribute is not ignored
	not assertions.assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# missing attributes in one result is not ignored
	not assertions.assert_equal_results(
		{{"spam": "SPAM", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)
	not assertions.assert_equal_results(
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
		{{"spam": "SPAM", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
	)

	# fallback for unexpected types
	assertions.assert_equal_results({"spam", "maps"}, {"spam", "maps"})
	not assertions.assert_equal_results({"spam", "maps"}, "spam")
	not assertions.assert_equal_results(
		# These are "objects" instead of the expected "set of objects"
		{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"},
		{"spam": "maps", "collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"},
	)
}

# regal ignore:rule-length
test_assert_equal_results_no_collections if {
	# Empty results
	assertions.assert_equal_results_no_collections(set(), set())
	assertions.assert_equal_results_no_collections({{}}, {{}})

	# collections attribute is ignored
	assertions.assert_equal_results_no_collections({{"collections": ["a", "b"]}}, {{}})
	assertions.assert_equal_results_no_collections({{}}, {{"collections": ["a", "b"]}})
	assertions.assert_equal_results_no_collections({{"collections": ["a", "b"]}}, {{"collections": ["c", "d"]}})
	assertions.assert_equal_results_no_collections(
		{{"spam": "maps", "collections": ["a", "b"]}},
		{{"spam": "maps", "collections": ["c", "d"]}},
	)

	# missing attributes in one result is not ignored
	not assertions.assert_equal_results_no_collections(
		{{"spam": "SPAM", "collections": ["a", "b"]}},
		{{"collections": ["c", "d"]}},
	)
	not assertions.assert_equal_results_no_collections(
		{{"collections": ["c", "d"]}},
		{{"spam": "SPAM", "collections": ["a", "b"]}},
	)

	# fallback for unexpected types
	assertions.assert_equal_results_no_collections({"spam", "maps"}, {"spam", "maps"})
	not assertions.assert_equal_results_no_collections({"spam", "maps"}, "spam")
	not assertions.assert_equal_results_no_collections(
		# These are "objects" instead of the expected "set of objects"
		{"spam": "maps", "collections": ["a", "b"]},
		{"spam": "maps", "collections": ["c", "d"]},
	)
}
