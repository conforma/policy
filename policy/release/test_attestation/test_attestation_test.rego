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

package test_attestation_test

import rego.v1

import data.lib.assertions
import data.test_attestation

_image_ref := "registry.io/repo/image@sha256:abc123"

_statement_digest := "sha256:stmt000000000000000000000000000000000000000000000000000000000001"

_provenance_digest := "sha256:prov000000000000000000000000000000000000000000000000000000000001"

_statement_ref := sprintf("registry.io/repo/image@%s", [_statement_digest])

_bundle_ref := "quay.io/konflux-ci/tekton-catalog/task-verify@sha256:task00000000000000000000000000000000000000000000000000000000001"

_trusted_task_rules := {"trusted_task_rules": {"allow": {"Trusted tasks": [{"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*"}]}}}

_referrer(digest, artifact_type) := {
	"mediaType": "application/vnd.oci.image.manifest.v1+json",
	"size": 100,
	"digest": digest,
	"artifactType": artifact_type,
	"ref": sprintf("registry.io/repo/image@%s", [digest]),
}

_statement_referrer := _referrer(_statement_digest, "application/vnd.in-toto+json")

_provenance_referrer := _referrer(_provenance_digest, "application/vnd.dsse.envelope.v1+json")

_mock_referrers(ref) := [_statement_referrer] if {
	ref == _image_ref
}

_mock_referrers(ref) := [_provenance_referrer] if {
	ref == _statement_ref
}

_slsa_v1_task := {
	"name": "pipelineTask",
	"content": base64.encode(json.marshal({
		"metadata": {"labels": {
			"tekton.dev/task": "verify-task",
			"tekton.dev/pipelineTask": "verify-task",
		}},
		"spec": {
			"params": [],
			"taskRef": {
				"resolver": "bundles",
				"params": [
					{"name": "name", "value": "verify-task"},
					{"name": "bundle", "value": _bundle_ref},
					{"name": "kind", "value": "task"},
				],
			},
		},
		"status": {
			"results": [{"name": "TEST_OUTPUT", "value": "{}"}],
			"steps": [{"name": "step1"}],
		},
	})),
}

_parse_digest(digest_str) := {algorithm: value} if {
	parts := split(digest_str, ":")
	algorithm := parts[0]
	value := parts[1]
}

_slsa_v1_provenance := {
	"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "statement", "digest": _parse_digest(_statement_digest)}],
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": [_slsa_v1_task],
		}},
	},
	"signatures": [{"keyid": "", "certificate": ""}],
}

_mock_verify_success(_, _) := {
	"success": true,
	"errors": [],
	"attestations": [_slsa_v1_provenance],
}

_mock_manifests(_) := {_bundle_ref: {"annotations": {"org.opencontainers.image.version": "1.0"}}}

_make_statement(predicate) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": predicate,
})

# Package-level mock blob functions for each test scenario

_mock_blob_passed(_) := _make_statement({
	"result": "PASSED",
	"configuration": [{"name": "clair-scan"}],
	"passedTests": ["test-a", "test-b"],
})

_mock_blob_failed_with_details(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "clair-scan"}],
	"failedTests": ["CVE-2024-1234", "CVE-2024-5678"],
})

_mock_blob_failed_no_details(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "sanity-check"}],
})

_mock_blob_warned(_) := _make_statement({
	"result": "WARNED",
	"configuration": [{"name": "deprecation-check"}],
	"warnedTests": ["deprecated-api-v1"],
})

_mock_blob_unknown_result(_) := _make_statement({
	"result": "ERROR",
	"configuration": [{"name": "lint-check"}],
})

_mock_blob_missing_result(_) := _make_statement({
	"configuration": [{"name": "incomplete-test"}],
	"passedTests": ["test-a"],
})

# --- Multi-attestation infrastructure ---

_statement_digest_2 := "sha256:stmt000000000000000000000000000000000000000000000000000000000002"

_statement_ref_2 := sprintf("registry.io/repo/image@%s", [_statement_digest_2])

_provenance_digest_2 := "sha256:prov000000000000000000000000000000000000000000000000000000000002"

_statement_referrer_2 := _referrer(_statement_digest_2, "application/vnd.in-toto+json")

_provenance_referrer_2 := _referrer(_provenance_digest_2, "application/vnd.dsse.envelope.v1+json")

_slsa_v1_provenance_2 := {
	"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"subject": [{"name": "statement", "digest": _parse_digest(_statement_digest_2)}],
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"resolvedDependencies": [_slsa_v1_task],
		}},
	},
	"signatures": [{"keyid": "", "certificate": ""}],
}

_mock_referrers_two(ref) := [_statement_referrer, _statement_referrer_2] if {
	ref == _image_ref
}

_mock_referrers_two(ref) := [_provenance_referrer] if {
	ref == _statement_ref
}

_mock_referrers_two(ref) := [_provenance_referrer_2] if {
	ref == _statement_ref_2
}

_mock_verify_two(ref, _) := {
	"success": true,
	"errors": [],
	"attestations": [_slsa_v1_provenance],
} if {
	contains(ref, "prov000000000000000000000000000000000000000000000000000000000001")
}

_mock_verify_two(ref, _) := {
	"success": true,
	"errors": [],
	"attestations": [_slsa_v1_provenance_2],
} if {
	contains(ref, "prov000000000000000000000000000000000000000000000000000000000002")
}

# Test Case 5: mixed PASSED + FAILED
_mock_blob_mixed(ref) := _make_statement({
	"result": "PASSED",
	"configuration": [{"name": "sanity-check"}],
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000001")
}

_mock_blob_mixed(ref) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "clair-scan"}],
	"failedTests": ["CVE-2024-9999"],
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000002")
}

# Test Case 11: WARNED + FAILED coexistence
_mock_blob_warned_and_failed(ref) := _make_statement({
	"result": "WARNED",
	"configuration": [{"name": "deprecation-check"}],
	"warnedTests": ["old-api"],
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000001")
}

_mock_blob_warned_and_failed(ref) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "clair-scan"}],
	"failedTests": ["CVE-2024-1111"],
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000002")
}

# Test Case 12: multiple FAILEDs
_mock_blob_multi_failed(ref) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "clair-scan"}],
	"failedTests": ["CVE-2024-1111"],
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000001")
}

_mock_blob_multi_failed(ref) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "sanity-check"}],
	"failedTests": ["format-error"],
}) if {
	contains(ref, "stmt000000000000000000000000000000000000000000000000000000000002")
}

# Test Case 9: custom configuration name
_mock_blob_custom_config(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "my-custom-test", "downloadLocation": "https://example.com"}],
	"failedTests": ["sub-test-1"],
})

# Test Case 10: empty configuration (fallback to "unknown test")
_mock_blob_no_config(_) := _make_statement({
	"result": "FAILED",
	"failedTests": ["sub-test-1"],
})

# Test Case 13: non-string result value
_mock_blob_non_string_result(_) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {
		"result": 42,
		"configuration": [{"name": "bad-producer"}],
	},
})

# --- Test Case 1: All attestations PASSED ---

test_all_passed_no_violations if {
	assertions.assert_empty(test_attestation.deny) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_passed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	assertions.assert_empty(test_attestation.warn) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_passed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 2: FAILED with failedTests array ---

test_failed_with_details if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"clair-scan\" has a failed result, failed tests CVE-2024-1234, CVE-2024-5678",
		"term": "clair-scan",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_failed_with_details
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 3: FAILED without failedTests array ---

test_failed_no_details if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"sanity-check\" has a failed result, failed tests (none listed)",
		"term": "sanity-check",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_failed_no_details
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 4: WARNED with warnedTests array ---

test_warned_with_details if {
	assertions.assert_empty(test_attestation.deny) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_warned
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	assertions.assert_equal_results(test_attestation.warn, {{
		"code": "test_attestation.no_test_warnings",
		"msg": "Test attestation \"deprecation-check\" has warnings, warned tests deprecated-api-v1",
		"term": "deprecation-check",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_warned
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 6: Unknown result value ---

test_unknown_result_value if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.test_result_known",
		"msg": "Test attestation \"lint-check\" has an unsupported result value \"ERROR\"",
		"term": "lint-check",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_unknown_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 7: Missing result field ---

test_missing_result_field if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.test_data_found",
		"msg": "Test attestation \"incomplete-test\" is missing the required result field",
		"term": "incomplete-test",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_missing_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 5: Mixed PASSED and FAILED ---

test_mixed_passed_and_failed if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"clair-scan\" has a failed result, failed tests CVE-2024-9999",
		"term": "clair-scan",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_two
		with ec.sigstore.verify_attestation as _mock_verify_two
		with ec.oci.blob as _mock_blob_mixed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	assertions.assert_empty(test_attestation.warn) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_two
		with ec.sigstore.verify_attestation as _mock_verify_two
		with ec.oci.blob as _mock_blob_mixed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 8: No test attestations at all ---

test_no_attestations_noop if {
	assertions.assert_empty(test_attestation.deny) with input.image.ref as _image_ref
		with ec.oci.image_referrers as []

	assertions.assert_empty(test_attestation.warn) with input.image.ref as _image_ref
		with ec.oci.image_referrers as []
}

# --- Test Case 9: _test_name extracts configuration name ---

test_test_name_from_configuration if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_custom_config
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	some r in results
	contains(r.msg, "\"my-custom-test\"")
}

# --- Test Case 10: Empty configuration falls back to "unknown test" ---

test_test_name_fallback if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_no_config
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	some r in results
	contains(r.msg, "\"unknown test\"")
}

# --- Test Case 11: WARNED + FAILED coexistence ---

test_warned_and_failed_coexist if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"clair-scan\" has a failed result, failed tests CVE-2024-1111",
		"term": "clair-scan",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_two
		with ec.sigstore.verify_attestation as _mock_verify_two
		with ec.oci.blob as _mock_blob_warned_and_failed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	assertions.assert_equal_results(test_attestation.warn, {{
		"code": "test_attestation.no_test_warnings",
		"msg": "Test attestation \"deprecation-check\" has warnings, warned tests old-api",
		"term": "deprecation-check",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_two
		with ec.sigstore.verify_attestation as _mock_verify_two
		with ec.oci.blob as _mock_blob_warned_and_failed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 12: Multiple FAILEDs across attestations ---

test_multiple_failures_deny if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_two
		with ec.sigstore.verify_attestation as _mock_verify_two
		with ec.oci.blob as _mock_blob_multi_failed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	count(results) == 2

	deny_codes := {r.code | some r in results}
	assertions.assert_equal(deny_codes, {"test_attestation.no_failed_tests"})

	deny_terms := {r.term | some r in results}
	assertions.assert_equal(deny_terms, {"clair-scan", "sanity-check"})

	every r in results {
		contains(r.msg, "has a failed result")
	}
}

test_multiple_failures_no_warn if {
	assertions.assert_empty(test_attestation.warn) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers_two
		with ec.sigstore.verify_attestation as _mock_verify_two
		with ec.oci.blob as _mock_blob_multi_failed
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 13: Non-string result value ---

test_non_string_result if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_non_string_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	count(results) == 1
	some r in results
	r.code == "test_attestation.test_result_known"
	contains(r.msg, "unsupported result value")
}

# --- Test Case 14: Missing predicate field ---

_mock_blob_missing_predicate(_) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
})

test_missing_predicate if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_missing_predicate
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	count(results) == 1
	some r in results
	r.code == "test_attestation.test_data_found"
	contains(r.msg, "unknown test")
}

# --- Test Case 15: Non-array failedTests value (is_array guard) ---

_mock_blob_non_array_failed_tests(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "string-tests"}],
	"failedTests": "not-an-array",
})

test_non_array_failed_tests if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"string-tests\" has a failed result, failed tests (none listed)",
		"term": "string-tests",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_non_array_failed_tests
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

_mock_blob_non_array_warned_tests(_) := _make_statement({
	"result": "WARNED",
	"configuration": [{"name": "object-tests"}],
	"warnedTests": {"not": "an-array"},
})

test_non_array_warned_tests if {
	assertions.assert_equal_results(test_attestation.warn, {{
		"code": "test_attestation.no_test_warnings",
		"msg": "Test attestation \"object-tests\" has warnings, warned tests (none listed)",
		"term": "object-tests",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_non_array_warned_tests
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 16: Empty failedTests array boundary ---

_mock_blob_empty_failed_tests(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "empty-array-test"}],
	"failedTests": [],
})

test_empty_failed_tests_array if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"empty-array-test\" has a failed result, failed tests (none listed)",
		"term": "empty-array-test",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_empty_failed_tests
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

_mock_blob_empty_warned_tests(_) := _make_statement({
	"result": "WARNED",
	"configuration": [{"name": "empty-warn-test"}],
	"warnedTests": [],
})

test_empty_warned_tests_array if {
	assertions.assert_equal_results(test_attestation.warn, {{
		"code": "test_attestation.no_test_warnings",
		"msg": "Test attestation \"empty-warn-test\" has warnings, warned tests (none listed)",
		"term": "empty-warn-test",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_empty_warned_tests
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}

# --- Test Case 17: Falsy result values ---

_mock_blob_false_result(_) := _make_statement({
	"result": false,
	"configuration": [{"name": "false-result-test"}],
})

test_false_result_value if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_false_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	count(results) == 1
	some r in results
	r.code == "test_attestation.test_data_found"
}

_mock_blob_null_result(_) := _make_statement({
	"result": null,
	"configuration": [{"name": "null-result-test"}],
})

test_null_result_value if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_null_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	count(results) == 1
	some r in results
	r.code == "test_attestation.test_result_known"
}

_mock_blob_empty_string_result(_) := _make_statement({
	"result": "",
	"configuration": [{"name": "empty-string-test"}],
})

test_empty_string_result_value if {
	results := test_attestation.deny with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_empty_string_result
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true

	count(results) == 1
	some r in results
	r.code == "test_attestation.test_result_known"
}

# --- Test Case 18: Non-string elements in failedTests array ---

_mock_blob_non_string_tests(_) := _make_statement({
	"result": "FAILED",
	"configuration": [{"name": "bad-array-test"}],
	"failedTests": ["CVE-2024-1234", 42, true],
})

test_non_string_test_list_elements if {
	assertions.assert_equal_results(test_attestation.deny, {{
		"code": "test_attestation.no_failed_tests",
		"msg": "Test attestation \"bad-array-test\" has a failed result, failed tests CVE-2024-1234",
		"term": "bad-array-test",
	}}) with input.image.ref as _image_ref
		with ec.oci.image_referrers as _mock_referrers
		with ec.sigstore.verify_attestation as _mock_verify_success
		with ec.oci.blob as _mock_blob_non_string_tests
		with ec.oci.image_manifests as _mock_manifests
		with data.trusted_task_rules as _trusted_task_rules.trusted_task_rules
		with data.rule_data.trusted_task_rules_enabled as true
}
