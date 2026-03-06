#
# METADATA
# title: Trusted Artifacts Conventions
# description: >-
#   Policies to verify that a Tekton task definition conforms to the expected conventions required
#   for using Trusted Artifacts.
#
package trusted_artifacts

import rego.v1

import data.lib.metadata
import data.lib.rule_data

import data.lib.k8s

# METADATA
# title: Parameter
# description: Trusted Artifact parameters follow the expected naming convention.
# custom:
#   short_name: parameter
#   failure_msg: The parameter %q of the Task %q does not use the _ARTIFACT suffix
#
deny contains result if {
	some param_name in _ta_parameters
	not _has_ta_suffix(param_name)
	result := metadata.result_helper(rego.metadata.chain(), [param_name, k8s.name_version(input)])
}

# METADATA
# title: Result
# description: Trusted Artifact results follow the expected naming convention.
# custom:
#   short_name: result
#   failure_msg: The result %q of the Task %q does not use the _ARTIFACT suffix
#
deny contains result if {
	some result_name in _ta_results
	not _has_ta_suffix(result_name)
	result := metadata.result_helper(rego.metadata.chain(), [result_name, k8s.name_version(input)])
}

# METADATA
# title: Workspace
# description: >-
#   Tasks that implement the Trusted Artifacts pattern should not allow general purpose workspaces
#   to share data. Instead, data should be passed around via Trusted Artifacts. Workspaces used for
#   other purposes, e.g. provide auth credentials, are allowed. Use the rule data key
#   `allowed_trusted_artifacts_workspaces` to specify which workspace names are allowed. By default
#   this value is empty which effectively disallows any workspace.
# custom:
#   short_name: workspace
#   failure_msg: General purpose workspace %q is not allowed
#   effective_on: 2024-07-07T00:00:00Z
#
deny contains result if {
	_uses_trusted_artifacts(input)
	some workspace in input.spec.workspaces
	not workspace.name in rule_data.rule_data("allowed_trusted_artifacts_workspaces")
	result := metadata.result_helper(rego.metadata.chain(), [workspace.name])
}

_ta_parameters contains param_name if {
	some step in input.spec.steps
	_is_ta_step(step)
	"use" in step.args
	some arg in step.args
	some arg_param in regex.find_n(`\$\(params\..*\)`, arg, -1)
	param_name := trim_prefix(trim_suffix(arg_param, ")"), "$(params.")
}

_ta_results contains result_name if {
	some step in input.spec.steps
	_is_ta_step(step)
	"create" in step.args
	some arg in step.args
	some arg_result in regex.find_n(`\$\(results\..*\.path\)`, arg, -1)
	result_name := trim_prefix(trim_suffix(arg_result, ".path)"), "$(results.")
}

_has_ta_suffix(name) if endswith(name, "_ARTIFACT")

_is_ta_step(step) if contains(step.image, "trusted-artifacts")

# _uses_trusted_artifacts relies on heuristics to determine if the given Task definition uses the
# Trusted Artifacts pattern. It does so my looking for any parameters or results which have the
# _ARTIFACT suffix in its name.
_uses_trusted_artifacts(task) if {
	params := {param.name | some param in task.spec.params}
	results := {result.name | some result in task.spec.results}
	all_names := params | results
	ta_names := {name |
		some name in all_names
		_has_ta_suffix(name)
	}
	count(ta_names) > 0
}
