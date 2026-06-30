package lib.tekton

import rego.v1

import data.lib.time as ectime

pipeline_label := "pipelines.openshift.io/runtime"

task_label := "build.appstudio.redhat.com/build_type"

latest_required_pipeline_tasks(pipeline) := _merged_required_task_list(pipeline, "newest")

current_required_pipeline_tasks(pipeline) := _merged_required_task_list(pipeline, "most_current")

# required_task_list is used by required_pipeline_task_data in tasks.rego
# as a boolean existence check. It concatenates raw time-based arrays
# across all matching build types.
required_task_list(pipeline) := pipeline_data if {
	selectors := pipeline_label_selectors(pipeline)
	pipeline_data := [entry |
		some selector in selectors
		entries := object.get(data["pipeline-required-tasks"], selector, [])
		some entry in entries
	]
	count(pipeline_data) > 0
}

# Resolves time-based entries per build type, unions task lists, and tracks
# per-task effective_on dates. Uses min(effective_on) for tasks shared across
# types. The top-level effective_on is max() for backward compatibility.
_merged_required_task_list(pipeline, mode) := {
	"effective_on": max_effective_on,
	"tasks": all_tasks,
	"effective_on_by_task": task_dates,
} if {
	selectors := pipeline_label_selectors(pipeline)

	resolved := [r |
		some selector in selectors
		entries := object.get(data["pipeline-required-tasks"], selector, [])
		count(entries) > 0
		r := _resolve(entries, mode)
	]

	count(resolved) > 0

	all_tasks := {_normalize_task(task) |
		some r in resolved
		some task in r.tasks
	}

	task_dates := {task: sort(dates_for_task)[0] |
		some task in all_tasks
		dates_for_task := [r.effective_on |
			some r in resolved
			some t in r.tasks
			_normalize_task(t) == task
		]
	}

	dates := [r.effective_on | some r in resolved]
	ordered_dates := sort(dates)
	max_effective_on := ordered_dates[count(ordered_dates) - 1]
}

# Returns per-task effective_on date, falling back to the global effective_on.
task_effective_on(required_tasks_data, task) := date if {
	date := required_tasks_data.effective_on_by_task[_normalize_task(task)]
} else := date if {
	date := required_tasks_data.effective_on
}

# Sorts array tasks (one-of alternatives) for consistent set/map keys.
_normalize_task(task) := sort(task) if is_array(task)

_normalize_task(task) := task if not is_array(task)

_resolve(entries, "newest") := ectime.newest(entries)

_resolve(entries, "most_current") := ectime.most_current(entries)

# pipeline_label_selectors returns the set of required task list names
# that should be used. When a pipeline has multiple build task types,
# all types are returned and their required tasks are unioned downstream.
pipeline_label_selectors(pipeline) := value if {
	not is_fbc # FBC builds share the docker build task; its label is unreliable for FBC

	# Labels of the build Task from the SLSA Provenance v1.0 of a PipelineRun
	value := {l | some build_task in build_tasks(pipeline); l := build_task.metadata.labels[task_label]}
	count(value) > 0
} else := value if {
	not is_fbc # FBC builds share the docker build task; its label is unreliable for FBC

	# Labels of the build Task from the SLSA Provenance v0.2 of a PipelineRun
	value := {l | some build_task in build_tasks(pipeline); l := build_task.invocation.environment.labels[task_label]}
	count(value) > 0
} else := value if {
	# PipelineRun labels found in the SLSA Provenance v1.0
	value := {pipeline.statement.predicate.buildDefinition.internalParameters.labels[pipeline_label]}
} else := value if {
	# PipelineRun labels found in the SLSA Provenance v0.2
	value := {pipeline.statement.predicate.invocation.environment.labels[pipeline_label]}
} else := value if {
	# Labels from a Tekton Pipeline definition
	value := {pipeline.metadata.labels[pipeline_label]}
} else := value if {
	# special handling for fbc pipelines, they're detected via image label
	is_fbc

	value := {"fbc"}
}

pipeline_name := input.metadata.name

# evaluates to true for FBC image builds, for which we cannot rely on the build
# task labels
is_fbc if {
	input.image.config.Labels["operators.operatorframework.io.index.configs.v1"]
}
