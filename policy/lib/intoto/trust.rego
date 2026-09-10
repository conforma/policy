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

# Chain-of-trust verification for in-toto statements.
#
# This file deliberately couples lib.intoto with lib.sigstore, lib.tekton,
# and ec.oci/ec.sigstore built-ins to verify that in-toto statements were
# produced by trusted pipelines. If the intoto package grows significantly
# beyond its current scope, consider extracting trust verification into
# a dedicated package (e.g. lib.verification).
#
# Cross-file dependency: this file references _artifact_type and
# _known_types defined in intoto.rego (same package).
#
# Trust model: "one valid provenance chain suffices." A statement enters the
# trusted view if ANY provenance referrer attached to the statement referrer
# provides valid Sigstore-attested SLSA provenance (as produced by Tekton
# Chains) with all tasks trusted. The associated view intentionally stops after
# signature verification so consumers can diagnose task-trust failures; it must
# not be treated as trusted. Not all referrers must verify.
#
# Fail-closed behavior: if blob fetching, JSON parsing, or _type
# validation fails for a referrer, that statement and its provenance are
# excluded (no error is emitted at this layer). Consumer deny rules surface
# the absence as a policy violation.

package lib.intoto

import rego.v1

import data.lib.oci
import data.lib.sigstore
import data.lib.tekton

_intoto_referrers contains referrer if {
	some referrer in ec.oci.image_referrers(input.image.ref)
	referrer.artifactType == _artifact_type
}

# Signature-verified statement/provenance associations before Tekton task trust
# is applied. Consumers must explicitly enforce task trust before treating a
# record from this view as trusted.
associated_statement_provenances contains result if {
	some referrer in _intoto_referrers
	some provenance in _verified_provenances(referrer)

	statement := oci.parsed_blob_from_image(referrer.ref)

	# regal ignore:leaked-internal-reference
	statement._type in _known_types

	result := {
		"statement": statement,
		"provenance": provenance,
	}
}

verified_statement_provenances contains result if {
	some result in associated_statement_provenances
	_all_tasks_trusted(result.provenance)
}

verified_statements contains statement if {
	some result in verified_statement_provenances
	statement := result.statement
}

verified_statements_by_predicate(predicate_type) := {statement |
	some statement in verified_statements
	statement.predicateType == predicate_type
}

# Filter complete {statement, provenance} records by the statement's predicate type.
# The predicate is only the selector; each result retains the full in-toto statement
# and its full trusted SLSA provenance attestation.
verified_statement_provenances_by_predicate(predicate_type) := {result |
	some result in verified_statement_provenances
	result.statement.predicateType == predicate_type
}

# Filter signature-verified statement/provenance associations by the statement's
# predicate type without applying Tekton task trust. Consumers must explicitly
# enforce task trust before treating these records as trusted.
associated_statement_provenances_by_predicate(predicate_type) := {result |
	some result in associated_statement_provenances
	result.statement.predicateType == predicate_type
}

_verified_provenances(referrer) := {att |
	verification := ec.sigstore.verify_attestation(referrer.ref, sigstore.opts)
	object.get(verification, "success", false) == true
	atts := object.get(verification, "attestations", [])
	some att in atts
	_attests_to_subject(att, referrer.digest)
}

_attests_to_subject(att, expected_digest) if {
	some subject in att.statement.subject
	subject_digest(subject) == expected_digest
}

_all_tasks_trusted(att) if {
	all_tasks := tekton.tasks(att)
	count(all_tasks) > 0
	bundle_refs := {tekton.task_ref(task).bundle |
		some task in all_tasks
		tekton.task_ref(task).bundle != ""
	}
	manifests := ec.oci.image_manifests(bundle_refs)
	untrusted := tekton.untrusted_task_refs(all_tasks, manifests)
	count(untrusted) == 0
}
