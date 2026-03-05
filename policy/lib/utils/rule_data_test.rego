package lib.utils_test

import rego.v1

import data.lib.utils
import data.lib

test_rule_data if {
	utils.assert_equal(
		[
			40, # key0 value comes from data.rule_data__configuration__
			30, # key1 value comes from data.rule_data_custom
			20, # key2 value comes from data.rule_data
			10, # key3 value comes from utils.rule_data_defaults
			[], # key4 value is not defined
		],
		[
			utils.rule_data("key0"),
			utils.rule_data("key1"),
			utils.rule_data("key2"),
			utils.rule_data("key3"),
			utils.rule_data("key4"),
		],
	) with data.rule_data__configuration__ as {"key0": 40}
		with data.rule_data_custom as {"key0": 30, "key1": 30}
		with data.rule_data as {"key0": 20, "key1": 20, "key2": 20}
		with utils.rule_data_defaults as {"key3": 10}
}

# Need this for 100% coverage
test_rule_data_defaults if {
	utils.assert_not_empty(utils.rule_data_defaults)
}
