package lib.utils_test

import rego.v1

import data.lib.utils
import data.lib

test_assert_equal if {
	utils.assert_equal("a", "a")
	utils.assert_equal({"a": 10}, {"a": 10})
	utils.assert_equal(["a"], ["a"])
	utils.assert_equal({"a"}, {"a"})
	not utils.assert_equal("a", "b")
	not utils.assert_equal({"a": 10}, {"a", 11})
	not utils.assert_equal(["a"], ["b"])
	not utils.assert_equal({"a"}, {"b"})
}

test_assert_not_equal if {
	utils.assert_not_equal("a", "b")
	utils.assert_not_equal({"a": 10}, {"a", 11})
	utils.assert_not_equal(["a"], ["b"])
	utils.assert_not_equal({"a"}, {"b"})
	not utils.assert_not_equal("a", "a")
	not utils.assert_not_equal({"a": 10}, {"a": 10})
	not utils.assert_not_equal(["a"], ["a"])
	not utils.assert_not_equal({"a"}, {"a"})
}

test_assert_empty if {
	utils.assert_empty([])
	utils.assert_empty({})
	utils.assert_empty(set())
	not utils.assert_empty(["a"])
	not utils.assert_empty({"a"})
	not utils.assert_empty({"a": "b"})
}

test_assert_not_empty if {
	utils.assert_not_empty(["a"])
	utils.assert_not_empty({"a"})
	utils.assert_not_empty({"a": "b"})
	not utils.assert_not_empty([])
	not utils.assert_not_empty({})
	not utils.assert_not_empty(set())
}

# regal ignore:rule-length
test_assert_equal_results if {
	# Empty results
	utils.assert_equal_results(set(), set())
	utils.assert_equal_results({{}}, {{}})

	# collections attribute is ignored
	utils.assert_equal_results({{"collections": ["a", "b"]}}, {{}})
	utils.assert_equal_results({{}}, {{"collections": ["a", "b"]}})
	utils.assert_equal_results({{"collections": ["a", "b"]}}, {{"collections": ["c", "d"]}})
	utils.assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"]}},
		{{"spam": "maps", "collections": ["c", "d"]}},
	)

	# effective_on attribute is ignored
	utils.assert_equal_results({{"effective_on": "2022-01-01T00:00:00Z"}}, {{}})
	utils.assert_equal_results({{}}, {{"effective_on": "2022-01-01T00:00:00Z"}})
	utils.assert_equal_results(
		{{"effective_on": "2022-01-01T00:00:00Z"}},
		{{"effective_on": "1970-01-01T00:00:00Z"}},
	)
	utils.assert_equal_results(
		{{"spam": "maps", "effective_on": "2022-01-01T00:00:00Z"}},
		{{"spam": "maps", "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# both collections and effective_on attributes are ignored
	utils.assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"spam": "maps", "collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# any other attribute is not ignored
	not utils.assert_equal_results(
		{{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)

	# missing attributes in one result is not ignored
	not utils.assert_equal_results(
		{{"spam": "SPAM", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
	)
	not utils.assert_equal_results(
		{{"collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"}},
		{{"spam": "SPAM", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"}},
	)

	# fallback for unexpected types
	utils.assert_equal_results({"spam", "maps"}, {"spam", "maps"})
	not utils.assert_equal_results({"spam", "maps"}, "spam")
	not utils.assert_equal_results(
		# These are "objects" instead of the expected "set of objects"
		{"spam": "maps", "collections": ["a", "b"], "effective_on": "2022-01-01T00:00:00Z"},
		{"spam": "maps", "collections": ["c", "d"], "effective_on": "1970-01-01T00:00:00Z"},
	)
}

# regal ignore:rule-length
test_assert_equal_results_no_collections if {
	# Empty results
	utils.assert_equal_results_no_collections(set(), set())
	utils.assert_equal_results_no_collections({{}}, {{}})

	# collections attribute is ignored
	utils.assert_equal_results_no_collections({{"collections": ["a", "b"]}}, {{}})
	utils.assert_equal_results_no_collections({{}}, {{"collections": ["a", "b"]}})
	utils.assert_equal_results_no_collections({{"collections": ["a", "b"]}}, {{"collections": ["c", "d"]}})
	utils.assert_equal_results_no_collections(
		{{"spam": "maps", "collections": ["a", "b"]}},
		{{"spam": "maps", "collections": ["c", "d"]}},
	)

	# missing attributes in one result is not ignored
	not utils.assert_equal_results_no_collections(
		{{"spam": "SPAM", "collections": ["a", "b"]}},
		{{"collections": ["c", "d"]}},
	)
	not utils.assert_equal_results_no_collections(
		{{"collections": ["c", "d"]}},
		{{"spam": "SPAM", "collections": ["a", "b"]}},
	)

	# fallback for unexpected types
	utils.assert_equal_results_no_collections({"spam", "maps"}, {"spam", "maps"})
	not utils.assert_equal_results_no_collections({"spam", "maps"}, "spam")
	not utils.assert_equal_results_no_collections(
		# These are "objects" instead of the expected "set of objects"
		{"spam": "maps", "collections": ["a", "b"]},
		{"spam": "maps", "collections": ["c", "d"]},
	)
}
