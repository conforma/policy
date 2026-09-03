# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

#
# METADATA
# title: Test attestation
# description: >-
#   Conforma can verify test result attestations attached to images as
#   in-toto statements. This package inspects the content of verified
#   test-result predicates and produces violations for failed tests and
#   warnings for warned tests. The package is a no-op when no test-result
#   attestations are present.
#
package test_attestation

import rego.v1

import data.lib.image
import data.lib.intoto
import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data
import data.lib.time as ectime

_all_test_attestations := intoto.verified_statements_by_predicate(intoto.predicate_test_result)

_attestation_timestamp(statement) := ts if {
	ts := statement.predicate.timestamp
	is_string(ts)
	ts != ""
}

_test_attestations contains statement if {
	# Group statements by name first (avoids re-scanning for each attestation)
	grouped := {name: statements |
		some name in {_test_name(s) | some s in _all_test_attestations}
		statements := {s |
			some s in _all_test_attestations
			_test_name(s) == name
		}
	}

	# For each group, find max timestamp once
	some name, statements in grouped
	max_ts := max({_attestation_timestamp(s) | some s in statements})

	# Filter to latest
	some statement in statements
	_attestation_timestamp(statement) == max_ts
}

_test_name(statement) := name if {
	predicate := object.get(statement, "predicate", {})
	config := object.get(predicate, "configuration", [])
	count(config) > 0
	name := config[0].name
} else := "unknown test"

_count_detail(predicate, key) := result if {
	n := object.get(predicate, key, 0)
	is_number(n)
	n > 0
	result := sprintf("%d", [n])
} else := "0"

_has_result(predicate, results, _) if {
	predicate.result in results
}

_has_result(predicate, _, count_key) if {
	n := object.get(predicate, count_key, 0)
	is_number(n)
	n > 0
}

# METADATA
# title: No failed informative test attestations
# description: >-
#   Produce a warning if any informative test attestation has a failed result.
#   Informative tests produce warnings instead of violations, allowing teams
#   to roll out new tests without blocking releases. The list of informative
#   tests is configurable by the "informative_test_attestations" key, and the
#   result type by the "failed_test_attestation_results" key in the rule data.
# custom:
#   short_name: no_failed_informative_test_attestations
#   failure_msg: 'Informative test attestation %q has a failed result, failures: %s'
#   solution: >-
#     An informative test attestation has a failed result. While this does
#     not block the release, review the test attestation output for details.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	some statement in _test_attestations
	_has_result(statement.predicate, rule_data.get("failed_test_attestation_results"), "failures")
	_test_name(statement) in rule_data.get("informative_test_attestations")
	detail := _count_detail(statement.predicate, "failures")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement), detail],
		_test_name(statement),
	)
}

# METADATA
# title: No test attestation warnings
# description: >-
#   Produce a warning if any test result attestation has a warned result.
#   Warned test names from the attestation predicate are included in the message
#   when available. The result type is configurable by the
#   "warned_test_attestation_results" key in the rule data.
# custom:
#   short_name: no_test_warnings
#   failure_msg: 'Test attestation %q has warnings, warnings: %s'
#   solution: >-
#     Review the test attestation output for warning details.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	some statement in _test_attestations
	_has_result(statement.predicate, rule_data.get("warned_test_attestation_results"), "warnings")
	detail := _count_detail(statement.predicate, "warnings")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement), detail],
		_test_name(statement),
	)
}

# METADATA
# title: Future required test attestations were found
# description: >-
#   Produce a warning when a test attestation that will be required in the
#   future is not currently present. This allows teams to prepare for
#   upcoming requirements without blocking current releases.
# custom:
#   short_name: future_required_test_attestations_found
#   failure_msg: '%s is missing and will be required on %s'
#   solution: >-
#     A test attestation that will be required at a future date is missing.
#     Ensure the test is included before the effective date.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	some missing_test in _missing_required_tests(_latest_required_tests)
	not missing_test in _current_required_tests
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[sprintf("Test attestation %q", [missing_test]), _latest_effective_on],
		missing_test,
	)
}

# METADATA
# title: No failed test attestations
# description: >-
#   Produce a violation if any non-informative test result attestation has
#   a failed result. Failed test names from the attestation predicate are
#   included in the message when available. The result type is configurable
#   by the "failed_test_attestation_results" key, and the list of informative
#   tests by the "informative_test_attestations" key in the rule data.
# custom:
#   short_name: no_failed_tests
#   failure_msg: 'Test attestation %q has a failed result, failures: %s'
#   solution: >-
#     Ensure all test attestations have a passing result. Review the
#     test attestation output for details.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations
	_has_result(statement.predicate, rule_data.get("failed_test_attestation_results"), "failures")
	not _test_name(statement) in rule_data.get("informative_test_attestations")
	detail := _count_detail(statement.predicate, "failures")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement), detail],
		_test_name(statement),
	)
}

# METADATA
# title: No unsupported test attestation result values
# description: >-
#   Ensure the result field of each test result attestation is a recognized
#   value. Valid values are configurable by the "supported_test_attestation_results"
#   key in the rule data. Defaults are PASSED, WARNED, FAILED, ERROR, and SKIPPED
#   per the in-toto test-result predicate specification.
# custom:
#   short_name: test_result_known
#   failure_msg: Test attestation %q has an unsupported result value %q
#   solution: >-
#     The test result attestation contains an unrecognized result value.
#     Valid values are configurable via rule data.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations
	statement.predicate.result
	not statement.predicate.result in rule_data.get("supported_test_attestation_results")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement), statement.predicate.result],
		_test_name(statement),
	)
}

# METADATA
# title: Test attestation data includes result
# description: >-
#   Each test result attestation must include a result field in its predicate.
#   Verify that the result field is present.
# custom:
#   short_name: test_data_found
#   failure_msg: Test attestation %q is missing the required result field
#   solution: >-
#     The test result attestation predicate must include a "result" field
#     with a recognized value such as PASSED, WARNED, or FAILED.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations
	not statement.predicate.result
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement)],
		_test_name(statement),
	)
}

# METADATA
# title: No erred test attestations
# description: >-
#   Produce a violation if any test result attestation has an erred result.
#   The result type is configurable by the "erred_test_attestation_results"
#   key in the rule data.
# custom:
#   short_name: no_erred_test_attestations
#   failure_msg: Test attestation %q has an erred result
#   solution: >-
#     A test attestation has an erred result, indicating an infrastructure
#     or execution failure. Review the test attestation and re-run the test.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations

	# "n/a": no count field for erred results in the predicate spec
	_has_result(statement.predicate, rule_data.get("erred_test_attestation_results"), "n/a")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement)],
		_test_name(statement),
	)
}

# METADATA
# title: No skipped test attestations
# description: >-
#   Produce a violation if any test result attestation has a skipped result.
#   A skipped result means a pre-requirement for executing the test was not met.
#   The result type is configurable by the "skipped_test_attestation_results"
#   key in the rule data.
# custom:
#   short_name: no_skipped_test_attestations
#   failure_msg: Test attestation %q has a skipped result
#   solution: >-
#     A test attestation was skipped, indicating a missing prerequisite
#     such as a scanner license. Ensure prerequisites are available and
#     re-run the test.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations

	# "n/a": no count field for skipped results in the predicate spec
	_has_result(statement.predicate, rule_data.get("skipped_test_attestation_results"), "n/a")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement)],
		_test_name(statement),
	)
}

# METADATA
# title: Test attestation subject matches image
# description: >-
#   Verify that each test-result attestation's subject includes the digest
#   of the image being evaluated. An attestation produced for a different
#   image should not satisfy this image's test requirements.
# custom:
#   short_name: subject_mismatch
#   failure_msg: Test attestation %q subject does not match image digest %q
#   solution: >-
#     The test result attestation was produced for a different image than
#     the one being evaluated. Ensure the test pipeline produces attestations
#     with the correct subject digest.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	img := image.parse(input.image.ref)
	img_digest := img.digest
	img_digest != ""
	some statement in _test_attestations
	not _subject_matches(statement, img_digest)
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement), img_digest],
		_test_name(statement),
	)
}

# METADATA
# title: Required test attestations were found
# description: >-
#   Produce a violation if a required test attestation is missing. Required
#   test attestations are configured via the "required-test-attestations"
#   rule data key with time-windowed entries. A test attestation is
#   considered present when a verified test-result statement has
#   predicate.configuration[0].name matching the required test name.
# custom:
#   short_name: required_test_attestations_found
#   failure_msg: Required test attestation %q is missing
#   solution: >-
#     Ensure all required test attestations are produced and attached to
#     the image. The required test attestation list is configurable via
#     the "required-test-attestations" key in the rule data.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some missing_test in _missing_required_tests(_current_required_tests)
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[missing_test],
		missing_test,
	)
}

# METADATA
# title: Required test attestations list was provided
# description: >-
#   Confirm that when the "required-test-attestations" rule data key is
#   provided, it resolves to a non-empty list of test names. This catches
#   misconfiguration where the key is present but all entries have empty
#   test lists or invalid effective_on dates.
# custom:
#   short_name: required_test_attestations_list_provided
#   failure_msg: Missing required required-test-attestations data
#   solution: >-
#     Ensure the rule data contains a "required-test-attestations" key
#     with at least one entry containing a non-empty "tests" array and
#     a valid "effective_on" date.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	count(_required_test_attestations_data) > 0
	not _resolved_required_tests
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format.
#   The keys are "supported_test_attestation_results", "failed_test_attestation_results",
#   "erred_test_attestation_results", "skipped_test_attestation_results",
#   "warned_test_attestation_results", "informative_test_attestations", and
#   "required-test-attestations".
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - redhat
#   - redhat_security
#   - policy_data
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_rule_data_errors contains error if {
	statuses := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {"enum": ["PASSED", "FAILED", "WARNED", "ERROR", "SKIPPED"]},
		"uniqueItems": true,
	}

	strings_array := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {"type": "string"},
		"uniqueItems": true,
	}

	items := [
		["supported_test_attestation_results", statuses],
		["failed_test_attestation_results", statuses],
		["erred_test_attestation_results", statuses],
		["skipped_test_attestation_results", statuses],
		["warned_test_attestation_results", statuses],
		["informative_test_attestations", strings_array],
	]

	some item in items
	key := item[0]
	schema := item[1]

	some e in j.validate_schema(rule_data.get(key), schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("required-test-attestations"),
		_required_test_attestations_schema,
	)
	error := {
		"message": sprintf("Rule data required-test-attestations has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	some i, entry in rule_data.get("required-test-attestations")
	effective_on := entry.effective_on
	not time.parse_rfc3339_ns(effective_on)
	error := {
		"message": sprintf(
			"required-test-attestations[%d].effective_on is not valid RFC3339 format: %q",
			[i, effective_on],
		),
		"severity": "failure",
	}
}

_subject_matches(statement, digest) if {
	some subject in object.get(statement, "subject", [])
	digest in intoto.subject_digests(subject)
}

_required_test_attestations_data := rule_data.get("required-test-attestations")

_resolved_required_tests if {
	ectime.most_current(_required_test_attestations_data).tests
}

_resolved_required_tests if {
	ectime.newest(_required_test_attestations_data).tests
}

default _current_required_tests := []

_current_required_tests := entry.tests if {
	entry := ectime.most_current(_required_test_attestations_data)
}

default _latest_required_tests := []

_latest_required_tests := entry.tests if {
	entry := ectime.newest(_required_test_attestations_data)
}

default _latest_effective_on := ""

_latest_effective_on := entry.effective_on if {
	entry := ectime.newest(_required_test_attestations_data)
}

_present_test_names contains name if {
	some statement in _test_attestations
	name := _test_name(statement)
}

_missing_required_tests(required_tests) := {test |
	some test in required_tests
	not test in _present_test_names
}

_required_test_attestations_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "array",
	"items": {
		"type": "object",
		"properties": {
			"effective_on": {"type": "string"},
			"tests": {
				"type": "array",
				"items": {"type": "string"},
				"uniqueItems": true,
				"minItems": 1,
			},
		},
		"required": ["effective_on", "tests"],
	},
	"uniqueItems": true,
}
