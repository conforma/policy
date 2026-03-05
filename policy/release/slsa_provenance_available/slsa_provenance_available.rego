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
package slsa_provenance_available

import rego.v1

import data.lib.utils
import data.lib
import data.lib.json as j

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
#     This field is set in the xref:cli:ROOT:configuration.adoc#_data_sources[data sources].
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	allowed_predicate_types := utils.rule_data(_rule_data_key)
	not att.statement.predicateType in allowed_predicate_types
	result := utils.result_helper(
		rego.metadata.chain(),
		[att.statement.predicateType, concat(", ", allowed_predicate_types)],
	)
}

# METADATA
# title: Allowed predicate types provided
# description: >-
#   Confirm the `allowed_predicate_types` rule data was provided, since it is required by the policy
#   rules in this package.
# custom:
#   short_name: allowed_predicate_types_provided
#   failure_msg: "%s"
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some e in _rule_data_errors
	result := utils.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# Verify allowed_predicate_types is a non-empty list of strings
_rule_data_errors contains error if {
	some e in j.validate_schema(
		utils.rule_data(_rule_data_key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_key := "allowed_predicate_types"
