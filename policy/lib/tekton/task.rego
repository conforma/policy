package lib.tekton

import rego.v1

import data.lib.arrays
import data.lib.time as ectime

default missing_required_tasks_data := false

missing_required_tasks_data if {
	count(data["required-tasks"]) == 0
}

# The latest set of required tasks. Tasks here are not required right now
# but will be required in the future.
latest_required_default_tasks := ectime.newest(data["required-tasks"])

# The set of required tasks that are required right now.
current_required_default_tasks := ectime.most_current(data["required-tasks"])

# tasks returns the set of tasks found in the object.
tasks(obj) := {task |
	some maybe_task in _maybe_tasks(obj)
	task := _slsa_task(maybe_task, obj)
}

# task from a slsav0.2 attestation
_slsa_task(task, attestation) := task if {
	# tasks in slsa v0.2 have a 'results' section.
	# the check below ensures that, in case we're dealing with a slsa v1 attestation,
	# we apply the correct task info extraction
	task.results
	ref := task_ref(task)
	ref.kind == "task"
}

# task from a slsav1 attestation
_slsa_task(task, attestation) := complete_task if {
	not task.results
	ref := task_ref(task)
	ref.kind == "task"

	task_params := _slsav1_task_params(task, attestation)
	task_results := _slsav1_task_results(task, attestation)

	complete_task := object.union(
		task,
		{
			"params": task_params,
			"results": task_results,
		},
	)
}

# _maybe_tasks returns a set of potential tasks.
# Handle tasks from a PipelineRun attestation.
_maybe_tasks(given) := given.statement.predicate.buildConfig.tasks

# Handle tasks from a Pipeline definition.
_maybe_tasks(given) := _tasks if {
	given.spec
	spec := object.get(given, "spec", {})
	_tasks := array.concat(
		object.get(spec, "tasks", []),
		object.get(spec, "finally", []),
	)
}

# handle tasks from a slsav1 attestation. for sample v1 schema, see:
# https://github.com/tektoncd/chains/blob/main/docs/predicate/slsa/v2.md#provenance-example-for-in-lined-buildconfig
_maybe_tasks(given) := given.statement.predicate.buildDefinition.externalParameters.runSpec.pipelineSpec.tasks

# tasks_names returns the set of task names extracted from the
# given object. It expands names to include the parameterized
# form, see task_names.
tasks_names(obj) := {name |
	some task in tasks(obj)
	some name in task_names(task)
}

# task_names returns the different names of the task. Additional
# names are produced for each parameter given to the task. For
# example, {"my-task", "my-task[spam=maps]" is produced for a
# task named "my-task" which takes the parameter "spam" with
# value "maps".
task_names(task) := names if {
	raw_name := task_name(task)
	name := split(raw_name, "[")[0] # don't allow smuggling task name with parameters
	params := {n |
		some k, v in task_params(task)
		n := sprintf("%s[%s=%s]", [name, k, v])
	}
	names := {name} | params
}

# task name from a v0.2 and v1.0 attestation
task_name(task) := task_ref(task).name

# returns a slsav0.2 pipeline task name
# the name field (which is the taskRun name) for slsav1.0 is metadata.name
# so this only passes for slsav0.2
pipeline_task_name(task) := task.name

# returns a slsav1.0 pipeline task name
pipeline_task_name(task) := value if {
	not task.name
	some label, value in task.metadata.labels
	label == "tekton.dev/pipelineTask"
}

# task_params returns an object where keys are parameter names
# and values are parameter values.
# Handle parameters of a task from a PipelineRun attestation.
task_params(task) := task.invocation.parameters if {
	not task.params
}

task_params(task) := task.invocation.parameters if {
	task.params
	count(task.params) == 0
}

# Handle parameters of a task in a Pipeline definition.
task_params(task) := params if {
	task.params
	count(task.params) > 0
	params := {name: value |
		some param in task.params
		name := _key_value(param, "name")
		value := _key_value(param, "value")
	}
}

# task_param returns the value of the given parameter in the task.
task_param(task, name) := task_params(task)[name]

# slsa v0.2 results
task_results(task) := task.results

# task_result returns the value of the given result in the task.
task_result(task, name) := value if {
	some result in task_results(task)
	result_name := _key_value(result, "name")
	result_name == name
	value := _key_value(result, "value")
}

task_result_endswith(task, suffix) := values if {
	results := arrays.sort_by("name", [result |
		some result in task_results(task)
		result_name := _key_value(result, "name")
		endswith(result_name, suffix)
	])
	values := [result.value | some result in results]
}

# slsa v0.2 step image
task_step_image_ref(step) := step.environment.image

# slsa v1.0 step image
task_step_image_ref(step) := step.imageID

# build_task returns the build task found in the attestation
build_tasks(attestation) := [task |
	some task in tasks(attestation)

	image_url := task_result_artifact_url(task)
	count(image_url) > 0

	image_digest := task_result_artifact_digest(task)
	count(image_digest) > 0
]

pre_build_tasks(attestation) := [task |
	some task in tasks(attestation)
	some pre_build_task_name in _pre_build_task_names
	task_name(task) == pre_build_task_name
]

_pre_build_task_names := ["run-script-oci-ta"]

# return the tasks that have "TEST_OUTPUT" as a result
tasks_output_result(attestation) := [task |
	some task in tasks(attestation)
	test_output := task_result(task, "TEST_OUTPUT")
	count(test_output) > 0
]

git_clone_tasks(attestation) := [task |
	some task in tasks(attestation)

	commit := task_result(task, "commit")
	count(trim_space(commit)) > 0

	url := task_result(task, "url")
	count(trim_space(url)) > 0
]

source_build_tasks(attestation) := [task |
	some task in tasks(attestation)

	url := trim_space(task_result(task, "SOURCE_IMAGE_URL"))
	count(url) > 0

	digest := trim_space(task_result(task, "SOURCE_IMAGE_DIGEST"))
	count(digest) > 0
]

# task_data returns the data relating to the task. If the task is
# referenced from a bundle, the "bundle" attribute is included.
task_data(task) := info if {
	r := task_ref(task)
	info := {"name": r.name, "bundle": r.bundle}
} else := info if {
	info := {"name": task_name(task)}
}

_key_value(obj, name) := value if {
	some key, value in obj
	key == name
}

# task_labels returns the key/value pair of task labels
task_labels(task) := labels if {
	# Task was the input, provided either as input to the task rules or SLSA v1
	# tasks from resolvedDependencies.content decoded and unmarshalled by
	# _maybe_tasks
	labels := task.metadata.labels
} else := labels if {
	# SLSA 0.2
	labels := task.invocation.environment.labels
}

# task_annotations returns the key/value pair of task annotations
task_annotations(task) := annotations if {
	# Task was the input, provided either as input to the task rules or SLSA v1
	# tasks from resolvedDependencies.content decoded and unmarshalled by
	# _maybe_tasks
	annotations := task.metadata.annotations
} else := annotations if {
	# SLSA 0.2
	annotations := task.invocation.environment.annotations
}

_slsav1_task_results(task, attestation) := results if {
	_slsav1_byproducts(attestation)

	# Get the pipeline task name for this task
	task_name := pipeline_task_name(task)

	# Extract all byproducts that belong to this task
	# Byproducts have names like "taskRunResults/<task_name>/<result_name>"
	prefix := sprintf("taskRunResults/%s/", [task_name])

	results := [result |
		some byproduct in _slsav1_byproducts(attestation)
		startswith(byproduct.name, prefix)

		# Extract the result name from "taskRunResults/<task_name>/<result_name>"
		parts := split(byproduct.name, "/")
		count(parts) == 3
		result_name := parts[2]

		# Decode the base64 content
		value := base64.decode(byproduct.content)

		result := {"name": result_name, "value": value}
	]
} else := []

_slsav1_task_params(task, attestation) := parameters if {
	task.params

	parameters := [resolved_param |
		some param in task.params
		param_name := _key_value(param, "name")

		template_value := _key_value(param, "value")
		resolved_value := _resolve_param_value(template_value, attestation)

		resolved_param := {"name": param_name, "value": resolved_value}
	]
} else := []

# Resolve a parameter value that may contain template expressions
_resolve_param_value(value, attestation) := resolved if {
	# Resolve pipeline params. e.g: $(params.prefetch-input)

	# Check if value contains $(params.xxx) pattern
	contains(value, "$(params.")

	# Extract the param name from $(params.xxx)
	parts := split(value, "$(params.")
	count(parts) == 2
	after_prefix := parts[1]
	param_parts := split(after_prefix, ")")
	param_name := param_parts[0]

	# Get pipeline-level params for resolving $(params.xxx) templates
	pipeline_params := object.get(
		attestation.statement.predicate.buildDefinition.externalParameters.runSpec,
		"params",
		[],
	)
	pipeline_params_map := {p.name: p.value | some p in pipeline_params}

	# Look up the resolved value from pipeline params
	base_value := pipeline_params_map[param_name]

	# Handle suffix after the template (e.g., ".prefetch")
	suffix := trim_left(after_prefix, concat("", [param_name, ")"]))
	resolved := concat("", [base_value, suffix])
} else := resolved if {
	# Resolve params coming from other taskRun results. e.g: $(tasks.clone-repository.results.SOURCE_ARTIFACT)

	# Check if value contains $(tasks.xxx.results.yyy) pattern
	contains(value, "$(tasks.")

	# Extract task name and result name from $(tasks.xxx.results.yyy)
	parts := split(value, "$(tasks.")
	count(parts) == 2
	after_prefix := parts[1]
	result_parts := split(after_prefix, ")")
	template_path := result_parts[0]

	# Parse "xxx.results.yyy" to extract task name and result name
	path_parts := split(template_path, ".results.")
	count(path_parts) == 2
	task_name := path_parts[0]
	result_name := path_parts[1]

	# Look up the result from byproducts
	# Byproducts have names like "taskRunResults/task_name/result_name"
	byproduct_name := sprintf("taskRunResults/%s/%s", [task_name, result_name])
	some byproduct in _slsav1_byproducts(attestation)
	byproduct.name == byproduct_name

	# Decode the base64 content
	resolved := base64.decode(byproduct.content)
} else := value

# No template - return value as-is

_slsav1_byproducts(attestation) := attestation.statement.predicate.runDetails.byproducts
