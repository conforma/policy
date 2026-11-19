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
# title: Required result defined (v2)
# description: >-
#   Verify if Task defines the required result. This is controlled by the `required_task_results`
#   rule data key. By default this is empty making this rule a no-op.
# custom:
#   short_name: required_v2
#   failure_msg: '%s'
#   effective_on: 2027-01-11T00:00:00Z
#
deny contains result if {
	some task in tkn_bundle.tasks
	some err in _errors_v2(task)
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

# METADATA
# title: Rule data provided (v2)
# description: >-
#   Confirm the expected `required_task_results` rule data key has been provided in the expected
#   format. Unlike rule_data_provided, a present value of the wrong type (for example a scalar
#   or a string containing JSON text) is rejected instead of silently skipping the check.
# custom:
#   short_name: rule_data_provided_v2
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   effective_on: 2027-01-11T00:00:00Z
#
deny contains result if {
	some e in _rule_data_errors_v2
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

# _errors_v2 mirrors _errors but reads declared results through _declared_results,
# which only yields results when `spec.results` is a proper array. A malformed
# `spec.results` therefore cannot mask a required result that is actually missing.
_errors_v2(task) := ({err |
	version := object.get(task.metadata, ["labels", "app.kubernetes.io/version"], "")
	version_constraints := {r.version | some r in rule_data.get(_rule_data_key)}
	not version in version_constraints

	some required in {r |
		some r in rule_data.get(_rule_data_key)
		task.metadata.name == r.task
		not r.version
	}
	found := [r |
		some r in _declared_results(task)
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
		some r in _declared_results(task)
		r.name == required.result
	]
	count(found) == 0
	err := sprintf("%q result not found in %q Task/v%s", [required.result, required.task, version])
}) | {err |
	# A Task whose metadata is missing or not an object has no usable name, so it can
	# never be matched against the rule data and the required-result check above would
	# silently pass. Report it, but only when required results are actually configured.
	count(rule_data.get(_rule_data_key)) > 0
	not task.metadata.name
	err := "Task has no usable metadata.name; required results cannot be verified"
}

# _declared_results returns the Task's results only when `spec.results` is a
# proper array. A wrong-container value (e.g. an object) or an absent value
# yields no results, so a malformed `spec.results` cannot mask a required result
# that is actually missing.
_declared_results(task) := task.spec.results if {
	is_array(task.spec.results)
} else := []

_rule_data_errors contains error if {
	some e in j.validate_schema(rule_data.get(_rule_data_key), _rule_data_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

# _rule_data_errors_v2 mirrors _rule_data_errors but validates the value as
# native rule data: a present scalar value is reported as a format violation
# instead of raising a builtin error that suppresses the result, and a string
# is never interpreted as serialized JSON.
_rule_data_errors_v2 contains error if {
	some e in j.validate_schema_native(rule_data.get(_rule_data_key), _rule_data_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_schema := {
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

_rule_data_key := "required_task_results"

_vstr(v) := s if {
	v != ""
	s := sprintf("/v%s", [v])
} else := ""
