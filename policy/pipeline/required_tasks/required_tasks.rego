#
# METADATA
# title: Required tasks
# description: >-
#   Konflux expects that certain Tekton tasks are executed during image builds.
#   This package includes policy rules to confirm that the pipeline definition
#   includes those required tasks.
#
package required_tasks

import rego.v1

import data.lib
import data.lib.tekton

# =============================================================================
# MANIFEST PRE-FETCHING
# Collect all bundle references and fetch manifests in a single batch call.
# =============================================================================

# Collect all unique bundle references from tasks in the pipeline definition
_all_bundle_refs contains bundle if {
	some task in tekton.tasks(input)
	bundle := tekton.task_ref(task).bundle
	bundle != ""
}

# Batch fetch all manifests at once using ec.oci.image_manifests
# This returns a map of bundle_ref -> manifest
_manifests := ec.oci.image_manifests(_all_bundle_refs)

# =============================================================================

# METADATA
# title: Required tasks found in pipeline definition
# description: >-
#   Produce a warning if a list of current or future required tasks does not exist
#   in the rule data.
# custom:
#   short_name: required_tasks_found
#   failure_msg: Required tasks do not exist for pipeline %q
warn contains result if {
	count(tekton.tasks(input)) > 0

	# check for current tasks
	not tekton.current_required_pipeline_tasks(input)

	# check for future tasks
	not tekton.latest_required_pipeline_tasks(input)
	result := lib.result_helper(rego.metadata.chain(), [tekton.pipeline_name])
}

# METADATA
# title: Missing future required task
# description: >-
#   Produce a warning when a task that will be required in the future
#   is not currently included in the Pipeline definition.
# custom:
#   short_name: missing_future_required_task
#   failure_msg: '%s is missing and will be required on %s'
warn contains result if {
	count(tekton.tasks(input)) > 0

	# Get missing tasks by comparing with the default required task list
	some required_task in _missing_tasks(latest_required_tasks.tasks)

	# If the required_task is also part of the current_required_tasks, do
	# not proceed with a warning since that's clearly a violation.
	not required_task in current_required_tasks.tasks
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[_format_missing(required_task, true), latest_required_tasks.effective_on],
		required_task,
	)
}

# METADATA
# title: Pipeline contains tasks
# description: >-
#   Confirm at least one task is present in the pipeline definition.
# custom:
#   short_name: tasks_found
#   failure_msg: No tasks found in pipeline
deny contains result if {
	input.kind == "Pipeline"
	count(tekton.tasks(input)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Missing required task
# description: >-
#   Ensure that the set of required tasks is included
#   in the Pipeline definition.
# custom:
#   short_name: missing_required_task
#   failure_msg: '%s is missing or outdated'
deny contains result if {
	count(tekton.tasks(input)) > 0

	# Get missing tasks by comparing with the default required task list
	some required_task in _missing_tasks(current_required_tasks.tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in latest_required_tasks.tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [_format_missing(required_task, false)], required_task)
}

# METADATA
# title: Required task list is present in rule data
# description: >-
#   Confirm the `required-tasks` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: required_tasks_list_present
#   failure_msg: The required tasks list is missing from the rule data
deny contains result if {
	tekton.missing_required_tasks_data
	not tekton.required_task_list(input)
	result := lib.result_helper(rego.metadata.chain(), [])
}

# _missing_tasks returns a set of task names that are in the given
# required_tasks, but not in the pipeline definition.
_missing_tasks(required_tasks) := {task |
	trusted := [task_name |
		some task in tekton.tasks(input)
		tekton.is_trusted_task(task, _manifests)
		some task_name in tekton.task_names(task)
	]

	some required_task in required_tasks
	some task in _any_missing(required_task, trusted)
}

_any_missing(required, tasks) := missing if {
	# one of required tasks is required
	is_array(required)

	# convert arrays to sets so we can intersect below
	req := lib.to_set(required)
	tsk := lib.to_set(tasks)
	count(req & tsk) == 0

	# no required tasks are in tasks
	missing := [required]
} else := missing if {
	# above could be false, so we need to doublecheck that we're not dealing
	# with an array
	not is_array(required)
	missing := {required |
		# a required task was not found in tasks
		not required in tasks
	}
} else := {}

# get the future tasks that are pipeline specific. If none exists
# get the default list
default latest_required_tasks := {"tasks": []}

latest_required_tasks := task_data if {
	task_data := tekton.latest_required_pipeline_tasks(input)
} else := task_data if {
	task_data := tekton.latest_required_default_tasks
}

# get the current tasks that are pipeline specific. If none exists
# get the default list
default current_required_tasks := {"tasks": []}

current_required_tasks := task_data if {
	task_data := tekton.current_required_pipeline_tasks(input)
} else := task_data if {
	task_data := tekton.current_required_default_tasks
}

# given an array a nice message saying one of the elements of the array,
# otherwise the quoted value
_format_missing(o, opt) := desc if {
	is_array(o)
	desc := sprintf(`One of "%s" tasks`, [concat(`", "`, o)])
} else := msg if {
	opt
	msg := sprintf("Task %q", [o])
} else := sprintf("Required task %q", [o])
