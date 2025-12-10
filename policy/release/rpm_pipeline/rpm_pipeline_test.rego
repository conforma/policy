package rpm_pipeline_test

import rego.v1

import data.lib
import data.rpm_pipeline

test_invalid_pipeline if {
	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [_valid_pipeline_task, _invalid_pipeline_task]},
		},
	}}]

	expected := {{
		"code": "rpm_pipeline.invalid_pipeline",
		"msg": "Task \"build\" uses invalid pipleline not_allowed, which is not in the list of valid pipelines: foobar",
	}}
	lib.assert_equal_results(expected, rpm_pipeline.deny) with data.rule_data.allowed_rpm_build_pipelines as ["foobar"]
		with input.attestations as attestations
}

test_valid_pipelines_met if {
	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [_valid_pipeline_task, _valid_pipeline_task_2]},
		},
	}}]

	lib.assert_empty(rpm_pipeline.deny) with data.rule_data.allowed_rpm_build_pipelines as ["foobar", "baz"]
		with input.attestations as attestations
}

_invalid_pipeline_task := {
	"name": "build",
	"status": "Succeeded",
	"ref": {"name": "init", "kind": "Task", "bundle": "quay.io/konflux-ci/tekton-catalog/task-init"},
	"invocation": {"environment": {"labels": {"build.appstudio.redhat.com/pipeline": "not_allowed"}}},
}

_valid_pipeline_task := {
	"name": "init",
	"status": "Succeeded",
	"ref": {"name": "init", "kind": "Task", "bundle": "quay.io/konflux-ci/tekton-catalog/task-init"},
	"invocation": {"environment": {"labels": {"build.appstudio.redhat.com/pipeline": "foobar"}}},
}

_valid_pipeline_task_2 := {
	"name": "get-rpm-sources",
	"status": "Succeeded",
	"ref": {"name": "init", "kind": "Task", "bundle": "quay.io/konflux-ci/tekton-catalog/task-init"},
	"invocation": {"environment": {"labels": {"build.appstudio.redhat.com/pipeline": "baz"}}},
}
