#
# METADATA
# description: >-
#   Enterprise Contract requires that each build was subjected
#   to a set of tests and that those tests all passed. This package
#   includes a set of rules to verify that.
#
package policy.release.test

import data.lib
import future.keywords.contains
import future.keywords.if
import future.keywords.in

# METADATA
# title: Test data found in task results
# description: >-
#   Ensure that at least one of the tasks in the pipeline includes a
#   TEST_OUTPUT task result, which is where Enterprise Contract expects
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

	result := lib.result_helper(rego.metadata.chain(), [])
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
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	with_results := [result | some r in lib.results_from_tests; result := r.value.result]
	count(with_results) != count(lib.results_from_tests)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: No unsupported test result values found
# description: >-
#   Ensure all test data result values are in the set of known/supported result values.
# custom:
#   short_name: test_results_known
#   failure_msg: Test '%s' has unsupported result '%s'
#   solution: >-
#     The test results should be of a known value. Values can be set as a
#     xref:ec-cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	all_unsupported := [u |
		some result in lib.results_from_tests
		test := result.value
		not test.result in lib.rule_data("supported_tests_results")
		u := {"task": result.name, "result": test.result}
	]

	count(all_unsupported) > 0
	some unsupported in all_unsupported
	result := lib.result_helper_with_term(
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
#   failure_msg: "Test %q failed"
#   solution: >-
#     There is a test that failed. Make sure that any task in the build pipeline
#     with a result named 'TEST_OUTPUT' does not fail.
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	some test in resulted_in(lib.rule_data("failed_tests_results"))
	not test in lib.rule_data("informative_tests")
	result := lib.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: No informative tests failed
# description: >-
#   Produce a warning if any informative tests have their result set to "FAILED".
#   The result type is configurable by the "failed_tests_results" key, and the list
#   of informative tests is configurable by the "informative_tests" key in the rule data.
# custom:
#   short_name: no_failed_informative_tests
#   failure_msg: "Informative test %q failed"
#   solution: >-
#     There is a test that failed. Make sure that any task in the build pipeline
#     with a result named 'TEST_OUTPUT' does not fail.
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#
warn contains result if {
	some test in resulted_in(lib.rule_data("failed_tests_results"))
	test in lib.rule_data("informative_tests")
	result := lib.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: No tests erred
# description: >-
#   Produce a violation if any tests have their result set to "ERROR".
#   The result type is configurable by the "erred_tests_results" key in the rule data.
# custom:
#   short_name: no_erred_tests
#   failure_msg: "Test %q erred"
#   solution: >-
#     There is a test that erred. Make sure that any task in the build pipeline
#     with a result named 'TEST_OUTPUT' does not err.
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#
deny contains result if {
	some test in resulted_in(lib.rule_data("erred_tests_results"))
	result := lib.result_helper_with_term(rego.metadata.chain(), [test], test)
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
#   failure_msg: "Test %q was skipped"
#   solution: >-
#     There is a test that was skipped. Make sure that each
#     task with a result named 'TEST_OUTPUT' was not skipped. You can find
#     which test was skipped by examining the 'result' key in the 'TEST_OUTPUT'.
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#   effective_on: 2024-01-14T00:00:00Z
#
deny contains result if {
	some test in resulted_in(lib.rule_data("skipped_tests_results"))
	result := lib.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# METADATA
# title: No tests produced warnings
# description: >-
#   Produce a warning if any tests have their result set to "WARNING".
#   The result type is configurable by the "warned_tests_results" key in the rule data.
# custom:
#   short_name: no_test_warnings
#   failure_msg: "Test %q returned a warning"
#   solution: >-
#     There is a task with result 'TEST_OUTPUT' that returned a result of 'WARNING'.
#     You can find which test resulted in 'WARNING' by examining the 'result' key
#     in the 'TEST_OUTPUT'.
#   collections:
#   - redhat
#   depends_on:
#   - test.test_data_found
#
warn contains result if {
	some test in resulted_in(lib.rule_data("warned_tests_results"))
	result := lib.result_helper_with_term(rego.metadata.chain(), [test], test)
}

# Collect all tests that have resulted with one of the given
# results and convert their name to "test:<name>" format
resulted_in(results) := {r |
	some result in lib.results_from_tests
	test := result.value
	test.result in results
	r := result.name
}
