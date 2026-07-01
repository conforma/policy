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

package lib.intoto_test

import rego.v1

import data.lib.assertions
import data.lib.intoto

test_statements_from_referrer if {
	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as [_referrer(
			"sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
			"application/vnd.in-toto+json",
		)]
		with ec.oci.blob as _mock_blob_test_result

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
	statement.predicate.result == "PASSED"
}

test_statements_from_referrer_v01 if {
	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as [_referrer(
			"sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
			"application/vnd.in-toto+json",
		)]
		with ec.oci.blob as _mock_blob_v01

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
}

test_statements_filters_unrelated_referrers if {
	mock_referrers := [
		_referrer(
			"sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
			"application/vnd.in-toto+json",
		),
		_referrer(
			"sha256:ccc0000000000000000000000000000000000000000000000000000000000ccc",
			"application/vnd.dev.cosign.simplesigning.v1+json",
		),
	]

	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.blob as _mock_blob_test_result

	count(result) == 1
}

test_statements_empty_when_no_referrers if {
	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as []

	count(result) == 0
}

test_statements_skips_non_intoto_json if {
	result := intoto.statements with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as [_referrer(
			"sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
			"application/vnd.in-toto+json",
		)]
		with ec.oci.blob as _mock_blob_not_intoto

	count(result) == 0
}

test_statements_by_predicate_filters_correctly if {
	mock_referrers := [
		_referrer(
			"sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa",
			"application/vnd.in-toto+json",
		),
		_referrer(
			"sha256:ddd0000000000000000000000000000000000000000000000000000000000ddd",
			"application/vnd.in-toto+json",
		),
	]

	result := intoto.statements_by_predicate(intoto.predicate_test_result) with input.image.ref as "registry.io/repo/image@sha256:abc123"
		with ec.oci.image_referrers as mock_referrers
		with ec.oci.blob as _mock_blob_mixed_predicates

	count(result) == 1
	some statement in result
	statement.predicateType == "https://in-toto.io/attestation/test-result/v0.1"
}

test_subject_digest if {
	assertions.assert_equal(intoto.subject_digest({"digest": {"sha256": "abc123"}}), "sha256:abc123")
	assertions.assert_equal(intoto.subject_digest({"digest": {"sha512": "def456"}}), "sha512:def456")
}

test_predicate_constants if {
	assertions.assert_equal(intoto.predicate_test_result, "https://in-toto.io/attestation/test-result/v0.1")
	assertions.assert_equal(intoto.predicate_vuln_scan, "https://in-toto.io/attestation/vulns/v0.2")
}

# Helper to build a referrer descriptor
_referrer(digest, artifact_type) := {
	"mediaType": "application/vnd.oci.image.manifest.v1+json",
	"size": 100,
	"digest": digest,
	"artifactType": artifact_type,
	"ref": sprintf("registry.io/repo/image@%s", [digest]),
}

_mock_blob_test_result(_) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"result": "PASSED", "resourceUri": "registry.io/repo/image@sha256:abc123"},
})

_mock_blob_v01(_) := json.marshal({
	"_type": "https://in-toto.io/Statement/v0.1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"result": "PASSED", "resourceUri": "registry.io/repo/image@sha256:abc123"},
})

_mock_blob_not_intoto(_) := json.marshal({"some": "random json", "not": "intoto"})

_mock_blob_mixed_predicates(ref) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/test-result/v0.1",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"result": "PASSED"},
}) if {
	contains(ref, "aaa")
}

_mock_blob_mixed_predicates(ref) := json.marshal({
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": "https://in-toto.io/attestation/vulns/v0.2",
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {"scanner": {"uri": "https://scanner.example.com"}},
}) if {
	contains(ref, "ddd")
}
