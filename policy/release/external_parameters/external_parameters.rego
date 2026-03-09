#
# METADATA
# title: External parameters
# description: >-
#   Verify the attribute .predicate.buildDefinition.externalParameters of a
#   SLSA Provenance v1.0 matches the expectation.
#
package external_parameters

import rego.v1

import data.lib
import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data

# METADATA
# title: Pipeline run params
# description: >-
#   Verify the PipelineRun was initialized with a set of expected parameters.
#   By default it asserts git-repo, git-revision, and output-image are provided
#   with non-empty values. This is configurable by the rule data key
#   `pipeline_run_params`. Any additional parameters are NOT allowed.
# custom:
#   short_name: pipeline_run_params
#   failure_msg: PipelineRun params, %v, do not match expectation, %v.
#
deny contains result if {
	some provenance in lib.pipelinerun_attestations

	param_names := {p.name |
		some p in provenance.statement.predicate.buildDefinition.externalParameters.runSpec.params
		p.value != ""
	}
	expected_names := {n | some n in rule_data.get(_rule_data_key)}

	expected_names != param_names
	result := metadata.result_helper(rego.metadata.chain(), [param_names, expected_names])
}

# METADATA
# title: PipelineRun params provided
# description: Confirm the `pipeline_run_params` rule data was provided.
# custom:
#   short_name: pipeline_run_params_provided
#   failure_msg: '%s'
#   solution: Provide a non-empty list of expected PipelineRun parameters.
#   collections:
#   - policy_data
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# METADATA
# title: Restrict shared volumes
# description: >-
#   Verify the PipelineRun did not use any pre-existing PersistentVolumeClaim
#   workspaces.
# custom:
#   short_name: restrict_shared_volumes
#   failure_msg: PipelineRun uses shared volumes, %v.
#
deny contains result if {
	some provenance in lib.pipelinerun_attestations
	shared_workspaces := {w |
		some w in provenance.statement.predicate.buildDefinition.externalParameters.runSpec.workspaces
		w.persistentVolumeClaim
	}
	count(shared_workspaces) > 0
	result := metadata.result_helper(rego.metadata.chain(), [shared_workspaces])
}

# Verify pipeline_run_params is a non-empty list of strings
_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get(_rule_data_key),
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

_rule_data_key := "pipeline_run_params"
