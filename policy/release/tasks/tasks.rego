#
# METADATA
# title: Tasks
# description: >-
#   Conforma expects that a set of tasks were
#   included in the pipeline build for each image to be
#   released. This package includes a set of rules to verify
#   that the expected tasks ran in the pipeline when the image
#   was built.
#   Required tasks for a pipeline are specified in a data source
#   provided at runtime. This data source features two primary
#   rule data keys: pipeline-required-tasks and required-tasks.
#   The pipeline-required-tasks key lists all required tasks broken
#   down by pipeline name, while required-tasks details a
#   default or baseline set of tasks. If your pipeline corresponds
#   to an entry under pipeline-required-tasks, those tasks will be prioritized;
#   otherwise, the system will default to the tasks listed under
#   required-tasks. Required tasks are listed by the names given to
#   them within the task definition. Optionally invocation parameter
#   of a Task can be also mandated by including the name and the value
#   in square brackets following the name of the task. For example: name[PARAM=val].
#   Only single parameter is supported, to assert multiple parameters repeat the
#   required task definition for each parameter seperately.
#
#
package tasks

import rego.v1

import data.lib
import data.lib.json as j
import data.lib.tekton

# METADATA
# title: Required tasks list for pipeline was provided
# description: >-
#   Produce a warning if the required tasks list rule data was not provided.
# custom:
#   short_name: pipeline_required_tasks_list_provided
#   failure_msg: Required tasks do not exist for pipeline
#   solution: >-
#     The required task list is contained as xref:cli:ROOT:configuration.adoc#_data_sources[data]
#     under the key 'required-tasks'. Make sure this list exists.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - tasks.pipeline_has_tasks
#
warn contains result if {
	not required_pipeline_task_data
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Future required tasks were found
# description: >-
#   Produce a warning when a task that will be required in the future
#   was not included in the PipelineRun attestation.
# custom:
#   short_name: future_required_tasks_found
#   failure_msg: '%s is missing and will be required on %s'
#   solution: >-
#     There is a task that will be required at a future date that is missing
#     from the build pipeline.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - tasks.pipeline_has_tasks
#
warn contains result if {
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
# title: Pipeline run includes at least one task
# description: >-
#   Ensure that at least one Task is present in the PipelineRun
#   attestation.
# custom:
#   short_name: pipeline_has_tasks
#   failure_msg: No tasks found in PipelineRun attestation
#   solution: >-
#     Make sure the build pipeline ran any tasks and that the build system is
#     generating a proper attestation.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#   - slsa3
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	count(tekton.tasks(att)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Successful pipeline tasks
# description: >-
#   Ensure that all of the Tasks in the Pipeline completed successfully. Note that
#   skipped Tasks are not taken into account and do not influence the outcome.
# custom:
#   short_name: successful_pipeline_tasks
#   failure_msg: Pipeline task %q did not complete successfully, %q
#   solution: >-
#     Make sure the build pipeline is properly configured so all the tasks can be
#     executed successfully.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#   - slsa3
#   depends_on:
#   - tasks.pipeline_has_tasks
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	some task in tekton.tasks(att)
	some status in _status(task)
	status != "Succeeded"
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tekton.pipeline_task_name(task), status], tekton.pipeline_task_name(task),
	)
}

# METADATA
# title: All required tasks were included in the pipeline
# description: >-
#   Ensure that the set of required tasks are included
#   in the PipelineRun attestation.
# custom:
#   short_name: required_tasks_found
#   failure_msg: '%s is missing'
#   solution: >-
#     Make sure all required tasks are in the build pipeline. The required task list
#     is contained as xref:cli:ROOT:configuration.adoc#_data_sources[data] under the key 'required-tasks'.
#   collections:
#   - redhat
#   depends_on:
#   - tasks.pipeline_has_tasks
#
deny contains result if {
	some required_task in _missing_tasks(current_required_tasks.tasks)

	# Don't report an error if a task is required now, but not in the future
	required_task in latest_required_tasks.tasks
	result := lib.result_helper_with_term(rego.metadata.chain(), [_format_missing(required_task, false)], required_task)
}

# METADATA
# title: All required tasks are from trusted tasks
# description: >-
#   Ensure that the all required tasks are resolved from trusted tasks.
# custom:
#   short_name: required_untrusted_task_found
#   failure_msg: '%s is required and present but not from a trusted task'
#   solution: >-
#     Make sure all required tasks in the build pipeline are resolved from
#     trusted tasks.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - tasks.pipeline_has_tasks
#
deny contains result if {
	required_task_names := current_required_tasks.tasks # e.g. [["buildah", "buildah-remote"], "clair-scan"]

	# flatten into a single array of strings
	flattened_required_tasks := flatten_list_to_sorted_array(required_task_names)

	some att in lib.pipelinerun_attestations
	some untrusted_task in tekton.untrusted_task_refs(lib.tasks_from_pipelinerun)

	# Check if any untrusted task matches a required task
	some required_task_name in flattened_required_tasks
	some untrusted_task_name in tekton.task_names(untrusted_task)

	untrusted_task_name == required_task_name
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[_format_missing(untrusted_task_name, false)],
		untrusted_task_name,
	)
}

# METADATA
# title: Required tasks list was provided
# description: >-
#   Confirm the `required-tasks` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: required_tasks_list_provided
#   failure_msg: Missing required required-tasks data
#   solution: >-
#     Make sure the xref:cli:ROOT:configuration.adoc#_data_sources[data sources] contains a key
#     'required-tasks' that contains a list of tasks that are required to run in the
#     build pipeline.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - tasks.pipeline_has_tasks
#
deny contains result if {
	tekton.missing_required_tasks_data
	not required_pipeline_task_data
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Pinned Task references
# description: >-
#   Ensure that all Tasks in the SLSA Provenance attestation use an immuntable reference to the
#   Task definition.
# custom:
#   short_name: pinned_task_refs
#   failure_msg: Task %s is used by pipeline task %s via an unpinned reference.
#   solution: >-
#     Make sure the build pipeline uses Tasks via pinned references. For example, if the git
#     resolver is used, use a commit ID instead of a branch name.
#   collections:
#   - redhat
#   depends_on:
#   - tasks.pipeline_has_tasks
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	some task in tekton.tasks(att)
	not tekton.task_ref(task).pinned
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tekton.task_name(task), tekton.pipeline_task_name(task)],
		tekton.task_name(task),
	)
}

# METADATA
# title: Task version unsupported
# description: >-
#   The Tekton Task used is or will be unsupported. The Task is annotated with
#   `build.appstudio.redhat.com/expires-on` annotation marking it as unsupported
#   after a certain date.
# custom:
#   short_name: unsupported
#   failure_msg: >-
#     Task %q is used by pipeline task %q is or will be unsupported as of %s. %s
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - tasks.pipeline_has_tasks
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	some task in tekton.tasks(att)

	annotations := tekton.task_annotations(task)

	expires_on := annotations[_expires_on_annotation]
	expiry_message := object.get(
		annotations,
		_expiry_msg_annotation,
		"Upgrade to a newer version of the Task.",
	)

	result := object.union(
		lib.result_helper_with_term(
			rego.metadata.chain(),
			[tekton.task_name(task), tekton.pipeline_task_name(task), expires_on, expiry_message],
			tekton.task_name(task),
		),
		{"effective_on": expires_on},
	)
}

# METADATA
# title: Data provided
# description: >-
#   Confirm the expected data keys have been provided in the expected format. The keys are
#   `pipeline-required-tasks` and `required-tasks`.
# custom:
#   short_name: data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the data is in the expected format.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some e in _data_errors
	result := lib.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# _missing_tasks returns a set of task names that are in the given
# required_tasks, but not in the PipelineRun attestation.
_missing_tasks(required_tasks) := {task |
	some att in lib.pipelinerun_attestations

	# all tasks on a PipelineRun
	tasks := tekton.tasks(att)
	count(tasks) > 0

	tasks_in_user_pipeline := [task_name |
		some task in tasks
		some task_name in tekton.task_names(task)
	]

	some required_task in required_tasks
	some task in _any_missing(required_task, tasks_in_user_pipeline)
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
	some att in lib.pipelinerun_attestations
	count(tekton.tasks(att)) > 0
	task_data := tekton.latest_required_pipeline_tasks(att)
} else := task_data if {
	task_data := tekton.latest_required_default_tasks
}

# get current required tasks. fall back to the default list if
# no label exists in the attestation
default current_required_tasks := {"tasks": []}

current_required_tasks := task_data if {
	some att in lib.pipelinerun_attestations
	count(tekton.tasks(att)) > 0
	task_data := tekton.current_required_pipeline_tasks(att)
} else := task_data if {
	task_data := tekton.current_required_default_tasks
}

## get the required task data for a pipeline with a label
required_pipeline_task_data := task_data if {
	some att in lib.pipelinerun_attestations
	count(tekton.tasks(att)) > 0
	task_data := tekton.required_task_list(att)
}

_status(task) := status if {
	# Handle SLSA Provenance v0.2
	task.status
	not task.status.conditions
	status := [s |
		s := task.status
	]
} else := status if {
	# Handle SLSA Provenance v1.0
	task.status.conditions
	status := [s |
		some condition in task.status.conditions
		condition.type == "Succeeded"
		s := _slsav1_status(condition)
	]

	# if task.status.conditions = [], we want ["MISSING"] returned
	count(status) > 0
} else := ["MISSING"]

_slsav1_status(condition) := status if {
	condition.status == "True"
	status := "Succeeded"
}

_slsav1_status(condition) := status if {
	condition.status == "False"
	status := "Failed"
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

_expires_on_annotation := "build.appstudio.redhat.com/expires-on"

_expiry_msg_annotation := "build.appstudio.redhat.com/expiry-message"

_data_errors contains error if {
	some e in j.validate_schema(
		data["pipeline-required-tasks"],
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"patternProperties": {".*": _required_tasks_schema},
		},
	)

	error := {
		"message": sprintf("Data pipeline-required-tasks has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

_data_errors contains error if {
	some e in j.validate_schema(
		data["required-tasks"],
		_required_tasks_schema,
	)

	error := {
		"message": sprintf("Data required-tasks has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

_data_errors contains error if {
	some i, entry in data["required-tasks"]
	effective_on := entry.effective_on
	not time.parse_rfc3339_ns(effective_on)
	error := {
		"message": sprintf(
			"required-tasks[%d].effective_on is not valid RFC3339 format: %q",
			[i, effective_on],
		),
		"severity": "failure",
	}
}

_data_errors contains error if {
	some key, entries in data["pipeline-required-tasks"]
	some i, entry in entries
	effective_on := entry.effective_on
	not time.parse_rfc3339_ns(effective_on)
	error := {
		"message": sprintf(
			"pipeline-required-tasks.%s[%d].effective_on is not valid RFC3339 format: %q",
			[key, i, effective_on],
		),
		"severity": "failure",
	}
}

_required_tasks_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "array",
	"items": {
		"type": "object",
		"properties": {
			"effective_on": {"type": "string"},
			"tasks": {
				"type": "array",
				"uniqueItems": true,
				"items": {"oneOf": [
					{"type": "string"},
					{
						"type": "array",
						"items": {"type": "string"},
						"uniqueItems": true,
						"minItems": 1,
					},
				]},
				"minItems": 1,
			},
		},
		"required": ["effective_on", "tasks"],
	},
	"uniqueItems": true,
}

# Helper function to flatten a nested list (containing strings and arrays of strings)
# into a single array of strings, with elements sorted and de-duplicated.
flatten_list_to_sorted_array(input_list) := sorted_array if {
	flat_set := {element |
		some element in input_list

		is_string(element)
		element != ""
	} | {element |
		some item in input_list

		is_array(item)
		some element in item
		is_string(element)
		element != ""
	}

	sorted_array := sort(flat_set)
}
