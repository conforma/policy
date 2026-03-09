#
# METADATA
# title: RPM Pipeline
# description: >-
#   This package provides rules for verifying the RPMs are built in an approved pipeline
#
package rpm_pipeline

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.rule_data
import data.lib.tekton

_pipeline_key := "build.appstudio.redhat.com/pipeline"

_rule_data_key := "allowed_rpm_build_pipelines"

# METADATA
# title: Task version invalid_pipeline
# description: >-
#   The Tekton Task used specifies an invalid pipeline. The Task is annotated with
#   `build.appstudio.redhat.com/pipeline` annotation, which must be in the set of
#   `allowed_rpm_build_pipelines` in the rule data.
# custom:
#   short_name: invalid_pipeline
#   failure_msg: >-
#     Task %q uses invalid pipleline %s, which is not in the list of valid pipelines: %s
#   collections:
#   - redhat_rpms
#   depends_on:
#   - tasks.pipeline_has_tasks
#
deny contains result if {
	some att in lib.pipelinerun_attestations
	some task in tekton.tasks(att)

	labels := tekton.task_labels(task)
	pipeline := labels[_pipeline_key]
	allowed_pipelines := rule_data.get(_rule_data_key)

	not pipeline in allowed_pipelines

	result := metadata.result_helper(
		rego.metadata.chain(),
		[tekton.pipeline_task_name(task), pipeline, concat(",", allowed_pipelines)],
	)
}
