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

test_runtime_data if {
	runtime := {"collector_data": {"RHSA": {}}, "scalar": 42}
	assertions.assert_equal(rule_data.runtime_data("collector_data"), {"RHSA": {}}) with data.rule_data__runtime__ as runtime
	assertions.assert_equal(rule_data.runtime_data("scalar"), 42) with data.rule_data__runtime__ as runtime
	assertions.assert_equal(rule_data.runtime_data("missing"), {}) with data.rule_data__runtime__ as runtime
}

test_runtime_data_without_namespace if {
	assertions.assert_equal(rule_data.runtime_data("collector_data"), {}) with data.rule_data__runtime__ as null
	assertions.assert_equal(rule_data.runtime_data("collector_data"), {}) with data.rule_data__runtime__ as {}
}

# Need this for 100% coverage
test_rule_data_defaults if {
	assertions.assert_not_empty(rule_data.defaults)
}

test_anchoring_errors_unanchored if {
	errors := rule_data.anchoring_errors("test_patterns") with data.rule_data as {"test_patterns": ["unanchored", "^anchored", "^.*ineffective", "^.+also_ineffective"]}
	assertions.assert_equal(count(errors), 3)
}

test_anchoring_errors_all_anchored if {
	errors := rule_data.anchoring_errors("test_patterns") with data.rule_data as {"test_patterns": ["^properly-anchored", "^specific-prefix"]}
	assertions.assert_empty(errors)
}

test_anchoring_errors_non_string_skipped if {
	errors := rule_data.anchoring_errors("test_patterns") with data.rule_data as {"test_patterns": [1, true, "^valid"]}
	assertions.assert_empty(errors)
}

test_anchoring_errors_empty_key if {
	errors := rule_data.anchoring_errors("nonexistent_key")
	assertions.assert_empty(errors)
}
