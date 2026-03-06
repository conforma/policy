#
# METADATA
# title: Attestation type
# description: >-
#   Sanity checks related to the format of the image build's attestation.
#
package attestation_type

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.rule_data
import data.lib.json as j

# METADATA
# title: Known attestation type found
# description: >-
#   Confirm the attestation found for the image has a known
#   attestation type.
# custom:
#   short_name: known_attestation_type
#   failure_msg: Unknown attestation type '%s'
#   solution: >-
#     Make sure the "_type" field in the attestation is supported. Supported types are configured
#     in xref:cli:ROOT:configuration.adoc#_data_sources[data sources].
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.pipelinerun_attestation_found
#
deny contains result if {
	some att in lib.pipelinerun_attestations

	# regal ignore:leaked-internal-reference
	att_type := att.statement._type
	not att_type in rule_data.rule_data(_rule_data_key)
	result := metadata.result_helper(rego.metadata.chain(), [att_type])
}

# METADATA
# title: Known attestation types provided
# description: Confirm the `known_attestation_types` rule data was provided.
# custom:
#   short_name: known_attestation_types_provided
#   failure_msg: '%s'
#   solution: Provide a list of known attestation types.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
}

# METADATA
# title: PipelineRun attestation found
# description: >-
#   Confirm at least one PipelineRun attestation is present.
# custom:
#   short_name: pipelinerun_attestation_found
#   failure_msg: Missing pipelinerun attestation
#   solution: >-
#     Make sure the attestation being verified was generated from a Tekton pipelineRun.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#
deny contains result if {
	count(lib.pipelinerun_attestations) == 0
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Deprecated policy attestation format
# description: >-
#   The Conforma CLI now places the attestation data in a different location.
#   This check fails if the expected new format is not found.
# custom:
#   short_name: deprecated_policy_attestation_format
#   failure_msg: Deprecated policy attestation format found
#   solution: Use a newer version of the Conforma CLI.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#   effective_on: 2023-08-31T00:00:00Z
deny contains result if {
	# Use input.attestations directly so we can detect the actual format in use.
	some att in input.attestations
	not att.statement
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# Verify known_attestation_types is a non-empty list of strings
_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.rule_data(_rule_data_key),
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

_rule_data_key := "known_attestation_types"
