package lib_test

import rego.v1

import data.lib

test_rule_data if {
	lib.assert_equal(
		[
			40, # key0 value comes from data.rule_data__configuration__
			30, # key1 value comes from data.rule_data_custom
			20, # key2 value comes from data.rule_data
			10, # key3 value comes from lib.rule_data_defaults
			[], # key4 value is not defined
		],
		[
			lib.rule_data("key0"),
			lib.rule_data("key1"),
			lib.rule_data("key2"),
			lib.rule_data("key3"),
			lib.rule_data("key4"),
		],
	) with data.rule_data__configuration__ as {"key0": 40}
		with data.rule_data_custom as {"key0": 30, "key1": 30}
		with data.rule_data as {"key0": 20, "key1": 20, "key2": 20}
		with lib.rule_data_defaults as {"key3": 10}
}

# Need this for 100% coverage
test_rule_data_defaults if {
	lib.assert_not_empty(lib.rule_data_defaults)
}

# We look in two places for these keys
test_required_task_keys if {
	lib.assert_equal("a", lib.rule_data("pipeline-required-tasks")) with data["pipeline-required-tasks"] as "a"
	lib.assert_equal("b", lib.rule_data("pipeline-required-tasks")) with data.rule_data["pipeline-required-tasks"] as "b"

	lib.assert_equal("a", lib.rule_data("required-tasks")) with data["required-tasks"] as "a"
	lib.assert_equal("b", lib.rule_data("required-tasks")) with data.rule_data["required-tasks"] as "b"

	# Confirm which location takes precedence if both are defined
	lib.assert_equal("b", lib.rule_data("pipeline-required-tasks")) with data["pipeline-required-tasks"] as "a"
		with data.rule_data["pipeline-required-tasks"] as "b"
	lib.assert_equal("b", lib.rule_data("required-tasks")) with data["required-tasks"] as "a"
		with data.rule_data["required-tasks"] as "b"
}
