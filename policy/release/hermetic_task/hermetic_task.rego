#
# METADATA
# title: Hermetic task
# description: >-
#   This package verifies that all the tasks in the attestation that
#   are required to be hermetic were invoked with the proper
#   parameters to perform a hermetic execution, including enabling
#   the Sonatype proxy when required.
#
package hermetic_task

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.rule_data
import data.lib.tekton

# METADATA
# title: Task called with hermetic param set
# description: >-
#   Verify the task in the PipelineRun attestation was invoked with the
#   proper parameters to make the task execution hermetic.
# custom:
#   short_name: hermetic
#   failure_msg: >-
#     Task '%s' was not invoked with the hermetic parameter set
#   solution: >-
#     Make sure the task has the input parameter 'HERMETIC' set to
#     'true'.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some not_hermetic_task in _not_hermetic_tasks
	result := metadata.result_helper(rego.metadata.chain(), [tekton.task_name(not_hermetic_task)])
}

# METADATA
# title: Hermetic build task has Sonatype proxy enabled
# description: >-
#   Verify that hermetic build tasks have the enable-hermeto-proxy
#   parameter set to true. This ensures that hermetic builds use
#   the Sonatype proxy for dependency resolution.
# custom:
#   short_name: hermeto_proxy_enabled
#   failure_msg: >-
#     Task '%s' is hermetic but does not have the enable-hermeto-proxy parameter set to true
#   solution: >-
#     Make sure the task has the input parameter 'enable-hermeto-proxy'
#     set to 'true'.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some task in _hermetic_tasks_without_proxy
	result := metadata.result_helper(rego.metadata.chain(), [tekton.task_name(task)])
}

_not_hermetic_tasks contains task if {
	some task in _required_hermetic_build_tasks
	not _task_is_hermetic(task)
}

_hermetic_tasks_without_proxy contains task if {
	some task in _required_hermetic_build_tasks
	_task_is_hermetic(task)
	not _task_has_proxy_enabled(task)
}

_required_hermetic_build_tasks contains task if {
	required_hermetic_tasks := rule_data.get("required_hermetic_tasks")
	some attestation in lib.pipelinerun_attestations
	some task in tekton.tasks(attestation)
	some required_hermetic_task in required_hermetic_tasks
	tekton.task_name(task) == required_hermetic_task
}

_task_is_hermetic(task) if {
	tekton.task_param(task, "HERMETIC")
	tekton.task_param(task, "HERMETIC") == "true"
}

_task_has_proxy_enabled(task) if {
	tekton.task_param(task, "enable-hermeto-proxy")
	tekton.task_param(task, "enable-hermeto-proxy") == "true"
}
