#
# METADATA
# title: SLSA - Provenance - Available
# description: >-
#   The SLSA Provenance Available requirement states the following:
#
#   "The provenance is available to the consumer in a format that the consumer accepts. The
#   format SHOULD be in-toto SLSA Provenance, but another format MAY be used if both producer
#   and consumer agree and it meets all the other requirements."
#
#   This package only accepts the in-toto SLSA Provenance format.
#
package policy.release.slsa_provenance_available

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib

# METADATA
# title: Expected attestation predicate type found
# description: >-
#   Verify that the predicateType field of the attestation indicates the in-toto SLSA Provenance
#   format was used to attest the PipelineRun.
# custom:
#   short_name: attestation_predicate_type_accepted
#   failure_msg: Attestation predicate type %q is not an expected type (%s)
#   solution: >-
#     The predicate type field in the attestation does not match the 'allowed_predicate_types' field.
#     This field is set in the xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources].
#   collections:
#   - minimal
#   - slsa1
#   - slsa2
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	allowed_predicate_types := lib.rule_data("allowed_predicate_types")
	not att.statement.predicateType in allowed_predicate_types
	result := lib.result_helper(
		rego.metadata.chain(),
		[att.statement.predicateType, concat(", ", allowed_predicate_types)],
	)
}
