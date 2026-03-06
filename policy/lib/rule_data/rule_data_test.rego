package lib.rule_data_test

import rego.v1

import data.lib.assertions
import data.lib.rule_data

test_rule_data if {
	assertions.assert_equal(
		[
			40, # key0 value comes from data.rule_data__configuration__
			30, # key1 value comes from data.rule_data_custom
			20, # key2 value comes from data.rule_data
			10, # key3 value comes from utils.rule_data_defaults
			[], # key4 value is not defined
		],
		[
			rule_data.rule_data("key0"),
			rule_data.rule_data("key1"),
			rule_data.rule_data("key2"),
			rule_data.rule_data("key3"),
			rule_data.rule_data("key4"),
		],
	) with data.rule_data__configuration__ as {"key0": 40}
		with data.rule_data_custom as {"key0": 30, "key1": 30}
		with data.rule_data as {"key0": 20, "key1": 20, "key2": 20}
		with rule_data.rule_data_defaults as {"key3": 10}
}

# Need this for 100% coverage
test_rule_data_defaults if {
	assertions.assert_not_empty(rule_data.rule_data_defaults)
}
