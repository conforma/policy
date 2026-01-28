# METADATA
# custom:
#   effective_on: 2001-02-03T00:00:00Z
#   scope: package
package lib.time_test

import rego.v1

import data.lib
import data.lib.time as lib_time

future_timestamp := time.add_date(time.now_ns(), 0, 0, 1)

# METADATA
# custom:
#   effective_on: 2004-05-06T00:00:00Z
test_when_rule_precedence if {
	lib_time.when(rego.metadata.chain()) == "2004-05-06T00:00:00Z"
}

test_when_package_precedence if {
	lib_time.when(rego.metadata.chain()) == "2001-02-03T00:00:00Z"
}

test_effective_current_time_ns if {
	now := time.now_ns()

	# with no config at all
	lib.assert_equal(lib_time.effective_current_time_ns, now)

	# no config.policy
	lib.assert_equal(lib_time.effective_current_time_ns, now) with data.config as {}

	# no config.policy.when_ns
	lib.assert_equal(lib_time.effective_current_time_ns, now) with data.config.policy as {}
	lib.assert_equal(
		lib_time.effective_current_time_ns,
		future_timestamp,
	) with data.config.policy.when_ns as future_timestamp
}

# regal ignore:rule-length
test_most_current if {
	# Ignore future item
	lib.assert_equal(
		lib_time.most_current([
			{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
			{"name": "ancient", "effective_on": "1985-01-01T00:00:00Z"},
		]),
		{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
	)

	# Produce no value when input is an empty list
	not lib_time.most_current([])

	# Produce no value if there are no current items
	not lib_time.most_current([
		{"name": "supernova", "effective_on": "2262-04-11T00:00:00Z"},
		{"name": "visionary", "effective_on": "2199-01-01T00:00:00Z"},
		{"name": "future", "effective_on": "2099-01-01T00:00:00Z"},
	])

	# Ignore items without effective_on
	lib.assert_equal(
		lib_time.most_current([
			{"name": "incomplete"},
			{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
			{"name": "lacking"},
		]),
		{"name": "past", "effective_on": "2022-01-01T00:00:00Z"},
	)
}

test_newest if {
	lib.assert_equal({"effective_on": "2262-04-11T00:00:00Z"}, lib_time.newest([
		{"effective_on": "2199-01-01T00:00:00Z"},
		{"effective_on": "2262-04-11T00:00:00Z"},
		{"effective_on": "2099-01-01T00:00:00Z"},
	]))
}
