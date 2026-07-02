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

package lib.intoto

import data.lib.oci
import rego.v1

_artifact_type := "application/vnd.in-toto+json"

# Spec-defined in-toto statement versions this library can parse.
# Intentionally separate from the policy-enforced known_attestation_types
# in attestation_type.rego — discovery should be permissive so the
# enforcement layer can report violations rather than silently dropping.
_known_types := {"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}

# statements returns the set of unsigned in-toto statements attached to the
# image as OCI referrers. Trust is established via Chains provenance
# verification; see verified_statements in trust.rego.
statements contains statement if {
	some referrer in ec.oci.image_referrers(input.image.ref)
	referrer.artifactType == _artifact_type
	statement := oci.parsed_blob(referrer.ref)

	# regal ignore:leaked-internal-reference
	statement._type in _known_types
}

# Filter statements by predicate type.
statements_by_predicate(predicate_type) := {statement |
	some statement in statements
	statement.predicateType == predicate_type
}

predicate_test_result := "https://in-toto.io/attestation/test-result/v0.1"

predicate_vuln_scan := "https://in-toto.io/attestation/vulns/v0.2"

# Converts a subject digest map (e.g., {"sha256": "abc..."}) to "algorithm:value" format.
subject_digest(subject) := digest if {
	some algorithm, value in subject.digest
	digest := concat(":", [algorithm, value])
}
