package lib.tekton

import rego.v1

import data.lib.sets
import data.lib.time as ectime

pipeline_label := "pipelines.openshift.io/runtime"

task_label := "build.appstudio.redhat.com/build_type"

latest_required_pipeline_tasks(pipeline) := pipeline_tasks if {
	pipeline_data := required_task_list(pipeline)
	pipeline_tasks := ectime.newest(pipeline_data)
}

current_required_pipeline_tasks(pipeline) := pipeline_tasks if {
	pipeline_data := required_task_list(pipeline)
	pipeline_tasks := ectime.most_current(pipeline_data)
}

# get the label from the pipelineRun attestation and return the
# required task list FOR that pipeline
required_task_list(pipeline) := pipeline_data if {
	pipeline_selector := pipeline_label_selector(pipeline)
	pipeline_data := data["pipeline-required-tasks"][pipeline_selector]
}

# pipeline_label_selector is a specialized function that returns the name of the
# required tasks list that should be used.
pipeline_label_selector(pipeline) := value if {
	not is_fbc # given that the build task is shared between fbc and docker builds we can't rely on the task's label

	# Labels of the build Task from the SLSA Provenance v1.0 of a PipelineRun
	values := [l | some build_task in build_tasks(pipeline); l := build_task.metadata.labels[task_label]]
	count(sets.to_set(values)) == 1
	value := values[0]
} else := value if {
	not is_fbc # given that the build task is shared between fbc and docker builds we can't rely on the task's label

	# Labels of the build Task from the SLSA Provenance v0.2 of a PipelineRun
	values := [l | some build_task in build_tasks(pipeline); l := build_task.invocation.environment.labels[task_label]]
	count(sets.to_set(values)) == 1
	value := values[0]
} else := value if {
	# PipelineRun labels found in the SLSA Provenance v1.0
	value := pipeline.statement.predicate.buildDefinition.internalParameters.labels[pipeline_label]
} else := value if {
	# PipelineRun labels found in the SLSA Provenance v0.2
	value := pipeline.statement.predicate.invocation.environment.labels[pipeline_label]
} else := value if {
	# Labels from a Tekton Pipeline definition
	value := pipeline.metadata.labels[pipeline_label]
} else := value if {
	# special handling for fbc pipelines, they're detected via image label
	is_fbc

	value := "fbc"
}

pipeline_name := input.metadata.name

# evaluates to true for FBC image builds, for which we cannot rely on the build
# task labels
is_fbc if {
	input.image.config.Labels["operators.operatorframework.io.index.configs.v1"]
}
