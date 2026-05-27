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

import data.lib.intoto
import data.lib.metadata

_test_attestations := intoto.verified_statements_by_predicate(intoto.predicate_test_result)

_test_name(statement) := name if {
	predicate := object.get(statement, "predicate", {})
	config := object.get(predicate, "configuration", [])
	count(config) > 0
	name := config[0].name
} else := "unknown test"

_test_list(predicate, key) := result if {
	value := object.get(predicate, key, [])
	is_array(value)
	items := [x | some x in value; is_string(x)]
	count(items) > 0
	result := concat(", ", items)
} else := "(none listed)"

# METADATA
# title: No failed test attestations
# description: >-
#   Produce a violation if any test result attestation has a result of "FAILED".
#   Failed test names from the attestation predicate are included in the message
#   when available.
# custom:
#   short_name: no_failed_tests
#   failure_msg: Test attestation %q has a failed result, failed tests %s
#   solution: >-
#     Ensure all test attestations have a passing result. Review the
#     failed tests listed in the attestation predicate.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations
	statement.predicate.result == "FAILED"
	failed := _test_list(statement.predicate, "failedTests")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement), failed],
		_test_name(statement),
	)
}

# METADATA
# title: No unsupported test attestation result values
# description: >-
#   Ensure the result field of each test result attestation is a recognized
#   value. Valid values are PASSED, WARNED, and FAILED per the in-toto
#   test-result predicate specification.
# custom:
#   short_name: test_result_known
#   failure_msg: Test attestation %q has an unsupported result value %q
#   solution: >-
#     The test result attestation contains an unrecognized result value.
#     Valid values are PASSED, WARNED, and FAILED.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some statement in _test_attestations
	statement.predicate.result
	not statement.predicate.result in {"PASSED", "FAILED", "WARNED"}
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
#     with a value of PASSED, WARNED, or FAILED.
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
# title: No test attestation warnings
# description: >-
#   Produce a warning if any test result attestation has a result of "WARNED".
#   Warned test names from the attestation predicate are included in the message
#   when available.
# custom:
#   short_name: no_test_warnings
#   failure_msg: Test attestation %q has warnings, warned tests %s
#   solution: >-
#     Review the warned tests listed in the attestation predicate.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
warn contains result if {
	some statement in _test_attestations
	statement.predicate.result == "WARNED"
	warned := _test_list(statement.predicate, "warnedTests")
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[_test_name(statement), warned],
		_test_name(statement),
	)
}
