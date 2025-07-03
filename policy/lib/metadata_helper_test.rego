package lib_test

import rego.v1

import data.lib

test_rule_annotations_with_annotations if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"failure_msg": "Test failure message",
		"pipeline_intention": ["build", "test"],
	}}

	chain := [
		{"annotations": rule_annotations, "path": ["data", "test", "deny"]},
		{"annotations": {}, "path": ["ignored", "path"]},
	]

	lib.assert_equal(rule_annotations, lib._rule_annotations(chain))
}

test_rule_annotations_empty_annotations if {
	empty_annotations := {}

	chain := [
		{"annotations": empty_annotations, "path": ["data", "test", "deny"]},
		{"annotations": {"some": "other"}, "path": ["ignored", "path"]},
	]

	lib.assert_equal(empty_annotations, lib._rule_annotations(chain))
}

test_rule_annotations_only_first_entry if {
	first_rule_annotations := {"custom": {"short_name": "FirstRule"}}
	second_rule_annotations := {"custom": {"short_name": "SecondRule"}}

	chain := [
		{"annotations": first_rule_annotations, "path": ["data", "test", "deny"]},
		{"annotations": second_rule_annotations, "path": ["other", "path"]},
	]

	# Should only return annotations from the first entry
	lib.assert_equal(first_rule_annotations, lib._rule_annotations(chain))
}

test_rule_annotations_single_entry_chain if {
	rule_annotations := {"custom": {"short_name": "SingleRule"}}

	chain := [{"annotations": rule_annotations, "path": ["data", "single", "deny"]}]

	lib.assert_equal(rule_annotations, lib._rule_annotations(chain))
}

test_release_restrictions_apply_with_matching_intention if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "release", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") matches one of the pipeline_intention values
	lib.assert_equal(true, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "release"
}

test_release_restrictions_apply_with_non_matching_intention if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") doesn't match any of the pipeline_intention values
	lib.assert_equal(false, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "release"
}

test_release_restrictions_apply_with_empty_pipeline_intention if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": [],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When pipeline_intention is an empty list, should return false
	lib.assert_equal(false, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "release"
}

test_release_restrictions_apply_without_pipeline_intention_field if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"failure_msg": "Some failure message",
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When pipeline_intention field is missing, should return false
	lib.assert_equal(false, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "release"
}

test_release_restrictions_apply_without_custom_field if {
	rule_annotations := {"other": {"some_field": "value"}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When custom field is missing, should return false
	lib.assert_equal(false, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "release"
}

test_release_restrictions_apply_with_null_rule_data if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "release", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") is null, should return false
	lib.assert_equal(false, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as null
}

test_release_restrictions_apply_with_multiple_matching_intentions if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["build", "release", "production", "test"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# When rule_data("pipeline_intention") matches one of multiple pipeline_intention values
	lib.assert_equal(true, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "production"
}

test_release_restrictions_apply_case_sensitivity if {
	rule_annotations := {"custom": {
		"short_name": "TestRule",
		"pipeline_intention": ["Build", "Release"],
	}}

	chain := [{"annotations": rule_annotations, "path": ["data", "test", "deny"]}]

	# Case sensitivity should be preserved
	lib.assert_equal(false, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "release"
	lib.assert_equal(true, lib.release_restrictions_apply(chain)) with data.rule_data.pipeline_intention as "Release"
}
