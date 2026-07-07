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

_test_attestations := intoto.verified_statements_by_predicate(intoto.predicate_test_result)

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
	predicate.result in {r | some r in results}
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
	_test_name(statement) in {t | some t in rule_data.get("informative_test_attestations")}
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
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations
	_has_result(statement.predicate, rule_data.get("failed_test_attestation_results"), "failures")
	not _test_name(statement) in {t | some t in rule_data.get("informative_test_attestations")}
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
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations
	statement.predicate.result
	not statement.predicate.result in {r | some r in rule_data.get("supported_test_attestation_results")}
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
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format.
#   The keys are "supported_test_attestation_results", "failed_test_attestation_results",
#   "erred_test_attestation_results", "skipped_test_attestation_results",
#   "warned_test_attestation_results", and "informative_test_attestations".
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - redhat
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

_subject_matches(statement, digest) if {
	some subject in object.get(statement, "subject", [])
	digest in intoto.subject_digests(subject)
}
