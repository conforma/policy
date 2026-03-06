#
# METADATA
# title: Test
# description: >-
#   Conforma requires that each build was subjected
#   to a set of tests and that those tests all passed. This package
#   includes a set of rules to verify that.
#
package test

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.rule_data
import data.lib.image
import data.lib.json as j

# METADATA
# title: No informative tests failed
# description: >-
#   Produce a warning if any informative tests have their result set to "FAILED".
#   The result type is configurable by the "failed_tests_results" key, and the list
#   of informative tests is configurable by the "informative_tests" key in the rule data.
# custom:
#   short_name: no_failed_informative_tests
#   failure_msg: The Task %q from the build Pipeline reports a failed informative test
#   solution: >-
#     There is a test that failed. Make sure that any task in the build pipeline
#     with a result named 'TEST_OUTPUT' does not fail. More information about the test
#     should be available in the logs for the build Pipeline.
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#
warn contains result if {
	some test in _resulted_in(rule_data.rule_data("failed_tests_results"), "failures")
	test in rule_data.rule_data("informative_tests")
	result := metadata.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: No tests produced warnings
# description: >-
#   Produce a warning if any tests have their result set to "WARNING".
#   The result type is configurable by the "warned_tests_results" key in the rule data.
# custom:
#   short_name: no_test_warnings
#   failure_msg: The Task %q from the build Pipeline reports a test contains warnings
#   solution: >-
#     There is a task with result 'TEST_OUTPUT' that returned a result of 'WARNING'.
#     You can find which test resulted in 'WARNING' by examining the 'result' key
#     in the 'TEST_OUTPUT'. More information about the test should be available in
#     the logs for the build Pipeline.
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#
warn contains result if {
	some test in _resulted_in(rule_data.rule_data("warned_tests_results"), "warnings")
	result := metadata.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: Test data found in task results
# description: >-
#   Ensure that at least one of the tasks in the pipeline includes a
#   TEST_OUTPUT task result, which is where Conforma expects
#   to find test result data.
# custom:
#   short_name: test_data_found
#   failure_msg: No test data found
#   solution: >-
#     Confirm at least one task in the build pipeline contains a result named TEST_OUTPUT.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	count(lib.pipelinerun_attestations) > 0 # make sure we're looking at a PipelineRun attestation
	results := lib.results_from_tests
	count(results) == 0 # there are none at all

	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Test data includes results key
# description: >-
#   Each test result is expected to have a `results` key. Verify that the `results`
#   key is present in all of the TEST_OUTPUT task results.
# custom:
#   short_name: test_results_found
#   failure_msg: Found tests without results
#   solution: >-
#     There was at least one result named TEST_OUTPUT found, but it did not contain a key
#     named 'result'. For a TEST_OUTPUT result to be valid, this key must exist.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	with_results := [r.value.result | some r in lib.results_from_tests]
	count(with_results) != count(lib.results_from_tests)
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: No unsupported test result values found
# description: >-
#   Ensure all test data result values are in the set of known/supported result values.
# custom:
#   short_name: test_results_known
#   failure_msg: The Task %q from the build Pipeline has an unsupported test result %q
#   solution: >-
#     The test results should be of a known value. Values can be set as a
#     xref:cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	all_unsupported := [u |
		some result in lib.results_from_tests
		test := result.value
		not test.result in rule_data.rule_data("supported_tests_results")
		u := {"task": result.name, "result": test.result}
	]

	count(all_unsupported) > 0
	some unsupported in all_unsupported
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[unsupported.task, unsupported.result],
		unsupported.task,
	)
}

# METADATA
# title: No tests failed
# description: >-
#   Produce a violation if any non-informative tests have their result set to "FAILED".
#   The result type is configurable by the "failed_tests_results" key, and the list
#   of informative tests is configurable by the "informative_tests" key in the rule data.
# custom:
#   short_name: no_failed_tests
#   failure_msg: The Task %q from the build Pipeline reports a failed test
#   solution: >-
#     There is a test that failed. Make sure that any task in the build pipeline
#     with a result named 'TEST_OUTPUT' does not fail. More information about the test
#     should be available in the logs for the build Pipeline.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	some test in _resulted_in(rule_data.rule_data("failed_tests_results"), "failures")
	not test in rule_data.rule_data("informative_tests")
	result := metadata.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: No tests erred
# description: >-
#   Produce a violation if any tests have their result set to "ERROR".
#   The result type is configurable by the "erred_tests_results" key in the rule data.
# custom:
#   short_name: no_erred_tests
#   failure_msg: The Task %q from the build Pipeline reports a test erred
#   solution: >-
#     There is a test that erred. Make sure that any task in the build pipeline
#     with a result named 'TEST_OUTPUT' does not err. More information about the test
#     should be available in the logs for the build Pipeline.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	some test in _resulted_in(rule_data.rule_data("erred_tests_results"), "n/a")
	result := metadata.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: No tests were skipped
# description: >-
#   Produce a violation if any tests have their result set to "SKIPPED".
#   A skipped result means a pre-requirement for executing the test was not met, e.g. a
#   license key for executing a scanner was not provided.
#   The result type is configurable by the "skipped_tests_results" key in the rule data.
# custom:
#   short_name: no_skipped_tests
#   failure_msg: The Task %q from the build Pipeline reports a test was skipped
#   solution: >-
#     There is a test that was skipped. Make sure that each
#     task with a result named 'TEST_OUTPUT' was not skipped. You can find
#     which test was skipped by examining the 'result' key in the 'TEST_OUTPUT'. More
#     information about the test should be available in the logs for the build Pipeline.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - test.test_data_found
#   effective_on: 2023-12-08T00:00:00Z
#
deny contains result if {
	some test in _resulted_in(rule_data.rule_data("skipped_tests_results"), "n/a")
	result := metadata.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `supported_tests_results`, `failed_tests_results`, `informative_tests`, `erred_tests_results`,
#   `skipped_tests_results`, and `warned_tests_results`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# METADATA
# title: Image digest is present in IMAGES_PROCESSED result
# description: >-
#   Ensure that task producing the IMAGES_PROCESSED result contains the
#   digests of the built image.
# custom:
#   short_name: test_all_images
#   failure_msg: Test '%s' did not process image with digest '%s'.
#   solution: >-
#     Found an image not processed by a task. Make sure that the task
#     processes and includes the image digest of all images in the
#     `IMAGES_PROCESSED` result.
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: 2024-05-29T00:00:00Z
#
deny contains result if {
	img := image.parse(input.image.ref)
	img_digest := img.digest

	some task in _grouped_processed_results_from_tests

	not img_digest in object.get(task.value, ["image", "digests"], [])
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[task.name, img_digest],
		task.name,
	)
}

# For a multi-arch matrix task we get records of multiple tasks with
# the same name and bundle. Combine digest lists from each them into
# one single list otherwise we get violations for matrix test tasks.
#
# We're making the assumption that there's no reason, other than matrix
# tasks, we would see the same task with the same name more than once
# in the pipelinerun.
#
_grouped_processed_results_from_tests contains result if {
	images_processed_results := lib.results_named(_task_test_image_result_name)

	some r1 in images_processed_results

	combined_digest_list := [digest |
		some r2 in images_processed_results
		r2.name == r1.name
		r2.bundle == r2.bundle
		some digest in r2.value.image.digests
	]

	# There is also a "pullspec" attribute alongside the "digests"
	# attribute in the original task result. I think it's identical
	# for each of the matrix tasks, so we could put it back in, but
	# we don't need it for the policy check so let's leave it out.

	result := object.union(r1, {"value": {"image": {"digests": combined_digest_list}}})
}

_task_test_image_result_name := "IMAGES_PROCESSED"

_did_result(test, results, _) if {
	test.result in results
}

_did_result(test, _, key) if {
	test[key] > 0
}

# Collect all tests that have resulted with one of the given
# results and convert their name to "test:<name>" format
_resulted_in(results, key) := {result.name |
	some result in lib.results_from_tests
	test := result.value
	_did_result(test, results, key)
}

_rule_data_errors contains error if {
	statuses := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {"enum": ["SUCCESS", "FAILURE", "WARNING", "SKIPPED", "ERROR"]},
		"uniqueItems": true,
	}

	strings_array := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {"type": "string"},
		"uniqueItems": true,
	}

	items := [
		["supported_tests_results", statuses],
		["failed_tests_results", statuses],
		["erred_tests_results", statuses],
		["skipped_tests_results", statuses],
		["warned_tests_results", statuses],
		["informative_tests", strings_array],
	]

	some item in items
	key := item[0]
	schema := item[1]

	some e in j.validate_schema(rule_data.rule_data(key), schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}
