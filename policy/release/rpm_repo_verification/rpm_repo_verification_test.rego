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

package rpm_repo_verification_test

import rego.v1

import data.lib.assertions
import data.lib_test
import data.rpm_repo_verification

test_success if {
	result_value := {"repos": [
		{
			"url": "https://example.com/repo/arm64",
			"gpg_key_id": "abcdef0123456789",
			"gpg_signature_verified": true,
			"metadata_checksums_verified": true,
		},
		{
			"url": "https://example.com/repo/x86_64",
			"gpg_key_id": "ABCDEF0123456789",
			"gpg_signature_verified": true,
			"metadata_checksums_verified": true,
		},
	]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	assertions.assert_empty(rpm_repo_verification.deny) with input.attestations as attestations
		with data.rule_data.allowed_rpm_repo_gpg_keys as ["abcdef0123456789", "ABCDEF0123456789"]
}

test_gpg_signature_failed if {
	result_value := {"repos": [{
		"url": "https://example.com/repo/arm64",
		"gpg_key_id": "abcdef0123456789",
		"gpg_signature_verified": false,
		"metadata_checksums_verified": true,
	}]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {{
		"code": "rpm_repo_verification.gpg_signature_verified",
		"msg": "Yum repository \"https://example.com/repo/arm64\" GPG signature verification failed",
	}}
	assertions.assert_equal_results(rpm_repo_verification.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_repo_gpg_keys as ["abcdef0123456789"]
}

test_metadata_checksums_failed if {
	result_value := {"repos": [{
		"url": "https://example.com/repo/arm64",
		"gpg_key_id": "abcdef0123456789",
		"gpg_signature_verified": true,
		"metadata_checksums_verified": false,
	}]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {{
		"code": "rpm_repo_verification.metadata_checksums_verified",
		"msg": "Yum repository \"https://example.com/repo/arm64\" metadata checksum verification failed",
	}}
	assertions.assert_equal_results(rpm_repo_verification.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_repo_gpg_keys as ["abcdef0123456789"]
}

test_disallowed_gpg_key if {
	result_value := {"repos": [{
		"url": "https://example.com/repo/arm64",
		"gpg_key_id": "abcdef0123456789",
		"gpg_signature_verified": true,
		"metadata_checksums_verified": true,
	}]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {{
		"code": "rpm_repo_verification.allowed_gpg_key",
		"msg": "Yum repository GPG key \"abcdef0123456789\" is not one of the allowed keys: [\"bcdef0123456789a\"]",
		"term": "abcdef0123456789",
	}}
	assertions.assert_equal_results(rpm_repo_verification.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_repo_gpg_keys as ["bcdef0123456789a"]
}

test_multiple_repos if {
	result_value := {"repos": [
		{
			"url": "https://example.com/repo/arm64",
			"gpg_key_id": "abcdef0123456789",
			"gpg_signature_verified": true,
			"metadata_checksums_verified": true,
		},
		{
			"url": "https://example.com/repo/x86_64",
			"gpg_key_id": "ABCDEF0123456789",
			"gpg_signature_verified": false,
			"metadata_checksums_verified": false,
		},
	]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {
		{
			"code": "rpm_repo_verification.gpg_signature_verified",
			"msg": "Yum repository \"https://example.com/repo/x86_64\" GPG signature verification failed",
		},
		{
			"code": "rpm_repo_verification.metadata_checksums_verified",
			"msg": "Yum repository \"https://example.com/repo/x86_64\" metadata checksum verification failed",
		},
	}
	assertions.assert_equal_results(rpm_repo_verification.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_repo_gpg_keys as ["abcdef0123456789"]
}

test_no_results if {
	assertions.assert_empty(rpm_repo_verification.deny) with input.attestations as []
		with data.rule_data.allowed_rpm_repo_gpg_keys as ["abcdef0123456789"]
}

test_result_format_invalid if {
	result_value := {"repos": [{
		"url": 123,
		"gpg_key_id": "abcdef0123456789",
		"gpg_signature_verified": "yes",
		"metadata_checksums_verified": true,
	}]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {
		{
			"code": "rpm_repo_verification.result_format",
			"msg": "Task result has unexpected format: repos.0.url: Invalid type. Expected: string, given: integer",
		},
		{
			"code": "rpm_repo_verification.result_format",
			"msg": "Task result has unexpected format: repos.0.gpg_signature_verified: Invalid type. Expected: boolean, given: string",
		},
	}
	assertions.assert_equal_results(rpm_repo_verification.deny, expected) with input.attestations as attestations
		with data.rule_data.allowed_rpm_repo_gpg_keys as ["abcdef0123456789"]
}

test_rule_data_provided if {
	result_value := {"repos": [{
		"url": "https://example.com/repo/arm64",
		"gpg_key_id": "abcdef0123456789",
		"gpg_signature_verified": true,
		"metadata_checksums_verified": true,
	}]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	d := {"allowed_rpm_repo_gpg_keys": [
		# Wrong data type
		1,
		# Duplicated items
		"abcdef0123456789",
		"abcdef0123456789",
	]}
	expected := {
		{
			"code": "rpm_repo_verification.rule_data_provided",
			"msg": "Rule data has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "rpm_repo_verification.rule_data_provided",
			"msg": "Unexpected format of GPG key '\\x01'",
			"severity": "failure",
		},
		{
			"code": "rpm_repo_verification.rule_data_provided",
			"msg": "Rule data has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(rpm_repo_verification.deny, expected) with input.attestations as attestations
		with data.rule_data as d
}

test_rule_data_not_provided if {
	result_value := {"repos": [{
		"url": "https://example.com/repo/arm64",
		"gpg_key_id": "abcdef0123456789",
		"gpg_signature_verified": true,
		"metadata_checksums_verified": true,
	}]}
	attestations := [_attestation_v1_0(result_value), _attestation_v0_2(result_value)]
	expected := {
		{
			"code": "rpm_repo_verification.rule_data_provided",
			"msg": "Rule data has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "rpm_repo_verification.allowed_gpg_key",
			"msg": "Yum repository GPG key \"abcdef0123456789\" is not one of the allowed keys: []",
			"term": "abcdef0123456789",
		},
	}
	assertions.assert_equal_results(rpm_repo_verification.deny, expected) with input.attestations as attestations
		with data.rule_data as {}
}

_attestation_v0_2(result_value) := lib_test.att_mock_helper_ref(
	rpm_repo_verification._result_name,
	result_value,
	"spam_v0_2",
	_bundle,
)

_attestation_v1_0(result_value) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {
				"params": [],
				"pipelineSpec": {"tasks": []},
			}},
		},
		"runDetails": {"byproducts": [{
			"name": concat("-", ["taskRunResults/spam_v1", rpm_repo_verification._result_name]),
			"value": result_value,
		}]},
	},
}}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
