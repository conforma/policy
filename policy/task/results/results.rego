#
# METADATA
# title: Tekton Task result
# description: Verify Tekton Task definitions provide expected results.
#
package results

import rego.v1

import data.lib.metadata
import data.lib.rule_data
import data.lib.tkn_bundle

import data.lib.json as j

# METADATA
# title: Required result defined
# description: >-
#   Verify if Task defines the required result. This is controlled by the `required_task_results`
#   rule data key. By default this is empty making this rule a no-op.
# custom:
#   short_name: required
#   failure_msg: '%s'
#
deny contains result if {
	some task in tkn_bundle.tasks
	some err in _errors(task)
	result := metadata.result_helper(rego.metadata.chain(), [err])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected `required_task_results` rule data key has been provided in the expected
#   format.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_errors(task) := {err |
	version := object.get(task.metadata, ["labels", "app.kubernetes.io/version"], "")
	version_constraints := {r.version | some r in rule_data.get(_rule_data_key)}
	not version in version_constraints

	some required in {r |
		some r in rule_data.get(_rule_data_key)
		task.metadata.name == r.task
		not r.version
	}
	found := [r |
		some r in task.spec.results
		r.name == required.result
	]
	count(found) == 0
	err := sprintf("%q result not found in %q Task%s (all versions)", [required.result, required.task, _vstr(version)])
} | {err |
	version := object.get(task.metadata, ["labels", "app.kubernetes.io/version"], "")
	some required in {r |
		some r in rule_data.get(_rule_data_key)
		task.metadata.name == r.task
		r.version == version
	}
	found := [r |
		some r in task.spec.results
		r.name == required.result
	]
	count(found) == 0
	err := sprintf("%q result not found in %q Task/v%s", [required.result, required.task, version])
}

_rule_data_errors contains error if {
	schema := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {
			"type": "object",
			"properties": {
				"task": {"type": "string"},
				"version": {"type": "string"},
				"result": {"type": "string"},
			},
			"additionalProperties": false,
			"required": ["task", "result"],
		},
		"uniqueItems": true,
	}

	some e in j.validate_schema(rule_data.get(_rule_data_key), schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_key := "required_task_results"

_vstr(v) := s if {
	v != ""
	s := sprintf("/v%s", [v])
} else := ""
