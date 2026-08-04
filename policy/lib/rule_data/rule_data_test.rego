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
			rule_data.get("key0"),
			rule_data.get("key1"),
			rule_data.get("key2"),
			rule_data.get("key3"),
			rule_data.get("key4"),
		],
	) with data.rule_data__configuration__ as {"key0": 40}
		with data.rule_data_custom as {"key0": 30, "key1": 30}
		with data.rule_data as {"key0": 20, "key1": 20, "key2": 20}
		with rule_data.defaults as {"key3": 10}
}

test_merged_rule_data_all_sources if {
	assertions.assert_equal(
		{"a": 1, "b": 2, "c": 3},
		rule_data.get("trusted_task_rules"),
	) with data.rule_data__configuration__ as {"trusted_task_rules": {"a": 1}}
		with data.rule_data_custom as {"trusted_task_rules": {"b": 2}}
		with data.rule_data as {"trusted_task_rules": {"c": 3}}
}

test_merged_rule_data_config_wins_on_conflict if {
	# configuration > custom > rule_data, matching the regular get precedence
	assertions.assert_equal(
		{"key": "from_config", "custom_only": 2, "base_only": 3},
		rule_data.get("trusted_task_rules"),
	) with data.rule_data__configuration__ as {"trusted_task_rules": {"key": "from_config"}}
		with data.rule_data_custom as {"trusted_task_rules": {"key": "from_custom", "custom_only": 2}}
		with data.rule_data as {"trusted_task_rules": {"key": "from_base", "base_only": 3}}
}

test_merged_rule_data_custom_and_default_only if {
	assertions.assert_equal(
		{"a": 1, "b": 2},
		rule_data.get("trusted_task_rules"),
	) with data.rule_data_custom as {"trusted_task_rules": {"a": 1}}
		with data.rule_data as {"trusted_task_rules": {"b": 2}}
}

test_merged_rule_data_default_only if {
	assertions.assert_equal(
		{"c": 3},
		rule_data.get("trusted_task_rules"),
	) with data.rule_data as {"trusted_task_rules": {"c": 3}}
}

test_merged_rule_data_config_only if {
	assertions.assert_equal(
		{"a": 1},
		rule_data.get("trusted_task_rules"),
	) with data.rule_data__configuration__ as {"trusted_task_rules": {"a": 1}}
}

test_merged_rule_data_base_and_config if {
	assertions.assert_equal(
		{"key": "from_config", "base_only": 2},
		rule_data.get("trusted_task_rules"),
	) with data.rule_data__configuration__ as {"trusted_task_rules": {"key": "from_config"}}
		with data.rule_data as {"trusted_task_rules": {"key": "from_base", "base_only": 2}}
}

test_merged_rule_data_custom_only if {
	assertions.assert_equal(
		{"a": 1},
		rule_data.get("trusted_task_rules"),
	) with data.rule_data_custom as {"trusted_task_rules": {"a": 1}}
}

test_merged_rule_data_none_defined if {
	assertions.assert_equal(
		{},
		rule_data.get("trusted_task_rules"),
	)
}

# Need this for 100% coverage
test_rule_data_defaults if {
	assertions.assert_not_empty(rule_data.defaults)
}
