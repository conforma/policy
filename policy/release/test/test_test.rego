package test_test

import rego.v1

import data.lib
import data.lib.tekton_test
import data.lib_test
import data.test

# Because TEST_OUTPUT isn't in the task results, the lib.results_from_tests will be empty
test_needs_non_empty_data if {
	# regal ignore:line-length
	slsav1_task := tekton_test.slsav1_task_result_ref("task2", [{"name": "NOT_TEST_OUTPUT", "type": "string", "value": {}}])
	attestations := [
		lib_test.att_mock_helper_ref("NOT_TEST_OUTPUT", {}, "task1", _bundle),
		tekton_test.slsav1_attestation([slsav1_task]),
	]
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_data_found",
		"msg": "No test data found",
	}}) with input.attestations as attestations
}

# There is a test result, but the data inside it doesn't include the "result" key
test_needs_tests_with_results if {
	slsav1_task := tekton_test.slsav1_task_result_ref("task2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"rezult": "SUCCESS"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name, {"rezult": "SUCCESS"},
			"task1", _bundle,
		),
		tekton_test.slsav1_attestation([slsav1_task]),
	]
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_results_found",
		"msg": "Found tests without results",
	}}) with input.attestations as attestations
}

test_needs_tests_with_results_mixed if {
	slsav1_bad_task := tekton_test.slsav1_task_result_ref("task3", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"rezult": "SUCCESS"},
	}])
	slsav1_good_task := tekton_test.slsav1_task_result_ref("task4", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "SUCCESS"},
	}])

	attestations := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "task1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"rezult": "SUCCESS"}, "task2", _bundle),
		tekton_test.slsav1_attestation([slsav1_good_task, slsav1_bad_task]),
	]
	lib.assert_equal_results(test.deny, {{
		"code": "test.test_results_found",
		"msg": "Found tests without results",
	}}) with input.attestations as attestations
}

test_success_data if {
	slsav1_good_task := tekton_test.slsav1_task_result_ref("task1", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "SUCCESS"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "task1", _bundle),
		tekton_test.slsav1_attestation([slsav1_good_task]),
	]
	lib.assert_empty(test.deny) with input.attestations as attestations
}

mock_a_failing_test := lib_test.att_mock_helper_ref(
	lib.task_test_result_name,
	{"result": "FAILURE"}, "failed_1", _bundle,
)

test_failure_data if {
	slsav1_task := tekton_test.slsav1_task_result_ref("task1", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "FAILURE"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "FAILURE"}, "failed_1", _bundle,
		),
		tekton_test.slsav1_attestation([slsav1_task]),
	]

	lib.assert_empty(test.warn) with input.attestations as attestations
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_failed_tests",
			"msg": "The Task \"failed_1\" from the build Pipeline reports a failed test",
			"term": "failed_1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "The Task \"task1\" from the build Pipeline reports a failed test",
			"term": "task1",
		},
	}) with input.attestations as attestations

	# Failed informative tests cause warnings, not violations
	lib.assert_empty(test.deny) with input.attestations as attestations
		with data.rule_data.informative_tests as ["task1", "failed_1"]
	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_failed_informative_tests",
			"msg": "The Task \"failed_1\" from the build Pipeline reports a failed informative test",
			"term": "failed_1",
		},
		{
			"code": "test.no_failed_informative_tests",
			"msg": "The Task \"task1\" from the build Pipeline reports a failed informative test",
			"term": "task1",
		},
	}) with input.attestations as attestations
		with data.rule_data.informative_tests as ["task1", "failed_1"]
}

mock_an_errored_test := lib_test.att_mock_helper_ref(
	lib.task_test_result_name,
	{"result": "ERROR"}, "errored_1", _bundle,
)

test_error_data if {
	slsav1_task := tekton_test.slsav1_task_result_ref("errored_2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "ERROR"},
	}])
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "ERROR"}, "errored_1", _bundle,
		),
		tekton_test.slsav1_attestation([slsav1_task]),
	]
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_erred_tests",
			"msg": "The Task \"errored_1\" from the build Pipeline reports a test erred",
			"term": "errored_1",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "The Task \"errored_2\" from the build Pipeline reports a test erred",
			"term": "errored_2",
		},
	}) with input.attestations as attestations
}

test_mix_data if {
	slsav1_errored_task := tekton_test.slsav1_task_result_ref("errored_2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "ERROR"},
	}])
	slsav1_failed_task := tekton_test.slsav1_task_result_ref("failed_2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "FAILURE"},
	}])
	attestations := [
		mock_a_failing_test,
		mock_an_errored_test,
		tekton_test.slsav1_attestation([slsav1_failed_task]),
		tekton_test.slsav1_attestation([slsav1_errored_task]),
	]
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_failed_tests",
			"msg": "The Task \"failed_1\" from the build Pipeline reports a failed test",
			"term": "failed_1",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "The Task \"errored_1\" from the build Pipeline reports a test erred",
			"term": "errored_1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "The Task \"failed_2\" from the build Pipeline reports a failed test",
			"term": "failed_2",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "The Task \"errored_2\" from the build Pipeline reports a test erred",
			"term": "errored_2",
		},
	}) with input.attestations as attestations
}

test_skipped_is_not_warning if {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "SKIPPED"}, "skipped_1", _bundle,
		),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("skipped_2", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPPED"},
		}])]),
	]
	lib.assert_empty(test.warn) with input.attestations as attestations
}

test_skipped_is_deny if {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "SKIPPED"}, "skipped_1", _bundle,
		),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("skipped_2", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPPED"},
		}])]),
	]
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_skipped_tests",
			"msg": "The Task \"skipped_1\" from the build Pipeline reports a test was skipped",
			"term": "skipped_1",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "The Task \"skipped_2\" from the build Pipeline reports a test was skipped",
			"term": "skipped_2",
		},
	}) with input.attestations as attestations
}

test_warning_is_warning if {
	attestations := [
		lib_test.att_mock_helper_ref(
			lib.task_test_result_name,
			{"result": "WARNING"}, "warning_1", _bundle,
		),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("warning_2", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "WARNING"},
		}])]),
	]
	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_test_warnings",
			"msg": "The Task \"warning_1\" from the build Pipeline reports a test contains warnings",
			"term": "warning_1",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "The Task \"warning_2\" from the build Pipeline reports a test contains warnings",
			"term": "warning_2",
		},
	}) with input.attestations as attestations
}

# regal ignore:rule-length
test_mixed_statuses if {
	test_results := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "error_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "success_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAILURE"}, "failure_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPPED"}, "skipped_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAILURE"}, "failure_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPPED"}, "skipped_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "WARNING"}, "warning_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "error_2", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "WARNING"}, "warning_2", _bundle),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("success_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SUCCESS"},
		}])]),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("failure_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "FAILURE"},
		}])]),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("error_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "ERROR"},
		}])]),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("warning_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "WARNING"},
		}])]),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("skipped_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPPED"},
		}])]),
	]

	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_erred_tests",
			"msg": "The Task \"error_1\" from the build Pipeline reports a test erred",
			"term": "error_1",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "The Task \"error_2\" from the build Pipeline reports a test erred",
			"term": "error_2",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "The Task \"failure_1\" from the build Pipeline reports a failed test",
			"term": "failure_1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "The Task \"failure_2\" from the build Pipeline reports a failed test",
			"term": "failure_2",
		},
		{
			"code": "test.no_failed_tests",
			"msg": "The Task \"failure_20\" from the build Pipeline reports a failed test",
			"term": "failure_20",
		},
		{
			"code": "test.no_erred_tests",
			"msg": "The Task \"error_20\" from the build Pipeline reports a test erred",
			"term": "error_20",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "The Task \"skipped_1\" from the build Pipeline reports a test was skipped",
			"term": "skipped_1",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "The Task \"skipped_2\" from the build Pipeline reports a test was skipped",
			"term": "skipped_2",
		},
		{
			"code": "test.no_skipped_tests",
			"msg": "The Task \"skipped_20\" from the build Pipeline reports a test was skipped",
			"term": "skipped_20",
		},
	}) with input.attestations as test_results

	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_test_warnings",
			"msg": "The Task \"warning_1\" from the build Pipeline reports a test contains warnings",
			"term": "warning_1",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "The Task \"warning_2\" from the build Pipeline reports a test contains warnings",
			"term": "warning_2",
		},
		{
			"code": "test.no_test_warnings",
			"msg": "The Task \"warning_20\" from the build Pipeline reports a test contains warnings",
			"term": "warning_20",
		},
	}) with input.attestations as test_results
}

test_unsupported_test_result if {
	test_results := [
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "EROR"}, "error_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCESS"}, "success_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "FAIL"}, "failure_1", _bundle),
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SKIPED"}, "skipped_1", _bundle),
		tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("skipped_20", [{
			"name": lib.task_test_result_name,
			"type": "string",
			"value": {"result": "SKIPED"},
		}])]),
	]

	lib.assert_equal_results(test.deny, {
		{
			"code": "test.test_results_known",
			"msg": "The Task \"error_1\" from the build Pipeline has an unsupported test result \"EROR\"",
			"term": "error_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "The Task \"failure_1\" from the build Pipeline has an unsupported test result \"FAIL\"",
			"term": "failure_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "The Task \"skipped_1\" from the build Pipeline has an unsupported test result \"SKIPED\"",
			"term": "skipped_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "The Task \"success_1\" from the build Pipeline has an unsupported test result \"SUCESS\"",
			"term": "success_1",
		},
		{
			"code": "test.test_results_known",
			"msg": "The Task \"skipped_20\" from the build Pipeline has an unsupported test result \"SKIPED\"",
			"term": "skipped_20",
		},
	}) with input.attestations as test_results
}

test_missing_wrong_attestation_type if {
	pr := lib_test.att_mock_helper_ref("some-result", {"result": "value"}, "task1", _bundle)
	tr := object.union(pr, {"statement": {"predicate": {"buildType": lib.tekton_task_run}}})
	tr_result := {"name": lib.task_test_result_name, "type": "string", "value": {"result": "SKIPED"}}

	# regal ignore:line-length
	pr_slsav1 := tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("skipped_20", [tr_result])])
	tr_slsav1 := object.union(
		pr_slsav1,
		{"statement": {"predicate": {"buildDefinition": {"buildType": lib.tekton_task_run}}}},
	)

	lib.assert_empty(test.deny) with input.attestations as [tr, tr_slsav1]
}

test_wrong_attestation_type if {
	pr := lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "ERROR"}, "errored_1", _bundle)
	tr := object.union(pr, {"statement": {"predicate": {"buildType": lib.tekton_task_run}}})
	tr_result := {"name": lib.task_test_result_name, "type": "string", "value": {"result": "ERROR"}}

	# regal ignore:line-length
	pr_slsav1 := tekton_test.slsav1_attestation([tekton_test.slsav1_task_result_ref("skipped_20", [tr_result])])
	tr_slsav1 := object.union(
		pr_slsav1,
		{"statement": {"predicate": {"buildDefinition": {"buildType": lib.tekton_task_run}}}},
	)
	lib.assert_empty(test.deny) with input.attestations as [tr, tr_slsav1]
}

test_all_image_processed if {
	# regal ignore:line-length
	digests_processed := {"image": {"digests": ["sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"]}}
	pipeline_run := lib_test.att_mock_helper_ref("IMAGES_PROCESSED", digests_processed, "success_23", _bundle)
	attestations := [
		pipeline_run,
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "errored_1", _bundle),
	]

	lib.assert_empty(test.deny) with input.attestations as attestations
		with input.image.ref as _bundle
}

test_all_images_not_processed if {
	digests_processed := {"image": {"digests": ["sha256:wrongDigest"]}}
	pipeline_run := lib_test.att_mock_helper_ref("IMAGES_PROCESSED", digests_processed, "success_23", _bundle)

	attestations := [
		pipeline_run,
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "errored_1", _bundle),
	]

	lib.assert_equal_results(test.deny, {{
		"code": "test.test_all_images",
		# regal ignore:line-length
		"msg": "Test 'success_23' did not process image with digest 'sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb'.",
		"term": "success_23",
	}}) with input.attestations as attestations
		with input.image.ref as _bundle
}

test_all_images_matrix_tasks if {
	# Matrix task scenario: same task name and bundle but different digests processed by each instance
	digests_task1 := {"image": {"digests": ["sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"]}}
	digests_task2 := {"image": {"digests": ["sha256:otherDigest"]}}

	matrix_task1 := lib_test.att_mock_helper_ref("IMAGES_PROCESSED", digests_task1, "matrix-test", _bundle)
	matrix_task2 := lib_test.att_mock_helper_ref("IMAGES_PROCESSED", digests_task2, "matrix-test", _bundle)

	attestations := [
		matrix_task1,
		matrix_task2,
		lib_test.att_mock_helper_ref(lib.task_test_result_name, {"result": "SUCCESS"}, "matrix-test", _bundle),
	]

	# Should pass because the grouped results combine digests from both matrix task instances
	lib.assert_empty(test.deny) with input.attestations as attestations
		with input.image.ref as _bundle
}

test_rule_data_provided if {
	d := {
		"supported_tests_results": [
			# Wrong type
			1,
			# Duplicated items
			"SUCCESS",
			"SUCCESS",
		],
		"failed_tests_results": [1],
		"erred_tests_results": [1],
		"skipped_tests_results": [1],
		"warned_tests_results": [1],
		"informative_tests": [
			# Wrong type
			1,
			# Duplicated items
			"SUCCESS",
			"SUCCESS",
		],
	}

	expected := {
		{
			"code": "test.rule_data_provided",
			# regal ignore:line-length
			"msg": `Rule data erred_tests_results has unexpected format: 0: 0 must be one of the following: "SUCCESS", "FAILURE", "WARNING", "SKIPPED", "ERROR"`,
			"severity": "failure",
		},
		{
			"code": "test.rule_data_provided",
			# regal ignore:line-length
			"msg": `Rule data failed_tests_results has unexpected format: 0: 0 must be one of the following: "SUCCESS", "FAILURE", "WARNING", "SKIPPED", "ERROR"`,
			"severity": "failure",
		},
		{
			"code": "test.rule_data_provided",
			"msg": "Rule data informative_tests has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "test.rule_data_provided",
			"msg": "Rule data informative_tests has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "test.rule_data_provided",
			# regal ignore:line-length
			"msg": `Rule data skipped_tests_results has unexpected format: 0: 0 must be one of the following: "SUCCESS", "FAILURE", "WARNING", "SKIPPED", "ERROR"`,
			"severity": "failure",
		},
		{
			"code": "test.rule_data_provided",
			"msg": "Rule data supported_tests_results has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "test.rule_data_provided",
			# regal ignore:line-length
			"msg": `Rule data supported_tests_results has unexpected format: 0: 0 must be one of the following: "SUCCESS", "FAILURE", "WARNING", "SKIPPED", "ERROR"`,
			"severity": "failure",
		},
		{
			"code": "test.rule_data_provided",
			# regal ignore:line-length
			"msg": `Rule data warned_tests_results has unexpected format: 0: 0 must be one of the following: "SUCCESS", "FAILURE", "WARNING", "SKIPPED", "ERROR"`,
			"severity": "failure",
		},
	}

	lib.assert_equal_results(test.deny, expected) with data.rule_data as d
}

test_results_and_counts if {
	task1 := tekton_test.slsav1_task_result_ref("task1", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "ERROR", "failures": 1, "warnings": 2, "successes": 3},
	}])
	task2 := tekton_test.slsav1_task_result_ref("task2", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "FAILURE", "failures": 1, "warnings": 0, "successes": 3},
	}])
	task3 := tekton_test.slsav1_task_result_ref("task3", [{
		"name": lib.task_test_result_name,
		"type": "string",
		"value": {"result": "SUCCESS", "failures": 0, "warnings": 2, "successes": 3},
	}])
	attestations := [tekton_test.slsav1_attestation([task1, task2, task3])]
	lib.assert_equal_results(test.deny, {
		{
			"code": "test.no_erred_tests",
			"msg": `The Task "task1" from the build Pipeline reports a test erred`,
			"term": "task1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": `The Task "task1" from the build Pipeline reports a failed test`,
			"term": "task1",
		},
		{
			"code": "test.no_failed_tests",
			"msg": `The Task "task2" from the build Pipeline reports a failed test`,
			"term": "task2",
		},
	}) with input.attestations as attestations
	lib.assert_equal_results(test.warn, {
		{
			"code": "test.no_test_warnings",
			"msg": `The Task "task1" from the build Pipeline reports a test contains warnings`,
			"term": "task1",
		},
		{
			"code": "test.no_test_warnings",
			"msg": `The Task "task3" from the build Pipeline reports a test contains warnings`,
			"term": "task3",
		},
	}) with input.attestations as attestations
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
