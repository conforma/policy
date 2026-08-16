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
# title: RPM Repository Verification
# description: >-
#   This package provides rules for verifying yum repository-level GPG signatures and checksum
#   chains as reported in the SLSA Provenance attestation. This is an alternative to individual
#   RPM signature verification for packages distributed via GPG-signed yum repositories.
#
package rpm_repo_verification

import rego.v1

import data.lib
import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data

# METADATA
# title: GPG signature verified
# description: >-
#   Each yum repository in the verification results must have a verified GPG signature on its
#   repomd.xml metadata file.
# custom:
#   short_name: gpg_signature_verified
#   failure_msg: "Yum repository %q GPG signature verification failed"
#   solution: >-
#     Ensure the yum repository metadata (repomd.xml) is signed with a valid GPG key and that the
#     signature can be verified.
#   collections:
#   - redhat
#   - redhat_rpms
#   - redhat_security
#   effective_on: 2026-11-01T00:00:00Z
#
deny contains result if {
	some repo in _repos
	not repo.gpg_signature_verified
	result := metadata.result_helper(rego.metadata.chain(), [repo.url])
}

# METADATA
# title: Metadata checksums verified
# description: >-
#   Each yum repository in the verification results must have verified metadata checksum chains,
#   ensuring the integrity of metadata files listed in repomd.xml.
# custom:
#   short_name: metadata_checksums_verified
#   failure_msg: "Yum repository %q metadata checksum verification failed"
#   solution: >-
#     Ensure the yum repository metadata checksum chain is intact. The checksums in repomd.xml must
#     match the actual metadata files.
#   collections:
#   - redhat
#   - redhat_rpms
#   - redhat_security
#   effective_on: 2026-11-01T00:00:00Z
#
deny contains result if {
	some repo in _repos
	not repo.metadata_checksums_verified
	result := metadata.result_helper(rego.metadata.chain(), [repo.url])
}

# METADATA
# title: Allowed GPG key
# description: >-
#   Each yum repository's GPG key must be in the list of allowed keys. The list of allowed keys
#   can be set via the `allowed_rpm_repo_gpg_keys` rule data.
# custom:
#   short_name: allowed_gpg_key
#   failure_msg: "Yum repository GPG key %q is not one of the allowed keys: %s"
#   solution: >-
#     Ensure the yum repository is signed with one of the allowed GPG keys configured in the
#     allowed_rpm_repo_gpg_keys rule data.
#   collections:
#   - redhat
#   - redhat_rpms
#   - redhat_security
#   effective_on: 2026-11-01T00:00:00Z
#
deny contains result if {
	some repo in _repos
	not lower(repo.gpg_key_id) in {lower(k) | some k in _allowed_rpm_repo_gpg_keys}
	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[repo.gpg_key_id, _allowed_rpm_repo_gpg_keys],
		repo.gpg_key_id,
	)
}

# METADATA
# title: Result format
# description: >-
#   Confirm the format of the RPM_REPO_VERIFICATION result is in the expected format.
# custom:
#   short_name: result_format
#   failure_msg: '%s'
#   collections:
#   - redhat
#   - redhat_rpms
#   - redhat_security
#   effective_on: 2026-11-01T00:00:00Z
#
deny contains result if {
	some error in _result_format_errors
	result := metadata.result_helper(rego.metadata.chain(), [error])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected `allowed_rpm_repo_gpg_keys` rule data key has been provided in the
#   expected format.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#   - redhat_security
#   effective_on: 2026-11-01T00:00:00Z
#
deny contains result if {
	count(_repo_verification_results) > 0
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_allowed_rpm_repo_gpg_keys := rule_data.get("allowed_rpm_repo_gpg_keys")

_repo_verification_results := lib.results_named(_result_name)

_repos contains repo if {
	some result in _repo_verification_results
	some repo in object.get(result.value, "repos", [])
}

_result_format_errors contains msg if {
	some result in _repo_verification_results
	value := json.marshal(result.value)
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"properties": {"repos": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"url": {"type": "string"},
						"gpg_key_id": {"type": "string"},
						"gpg_signature_verified": {"type": "boolean"},
						"metadata_checksums_verified": {"type": "boolean"},
					},
					"additionalProperties": true,
				},
			}},
			"additionalProperties": true,
		},
	)[1]
	msg := sprintf("Task result has unexpected format: %s", [violation.error])
}

_rule_data_errors contains error if {
	some e in j.validate_schema(
		_allowed_rpm_repo_gpg_keys,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)
	error := {
		"message": sprintf("Rule data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	some key in _allowed_rpm_repo_gpg_keys
	not _is_valid_key(key)
	error := {
		"message": sprintf("Unexpected format of GPG key %q", [key]),
		"severity": "failure",
	}
}

_is_valid_key(key) if {
	regex.match(`^[a-fA-F0-9]{16}$`, key)
}

_result_name := "RPM_REPO_VERIFICATION"
