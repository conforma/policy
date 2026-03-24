package checks_test

import rego.v1

import data.checks
import data.lib

opa_inspect_valid := {
	"namespaces": {
		"data.attestation_task_bundle": ["policy/release/attestation_task_bundle.rego"],
		"data.attestation_type": ["policy/release/attestation_type.rego"],
	},
	"annotations": [
		{
			"annotations": {
				"description": "Check if the Tekton Bundle used for the Tasks in the Pipeline definition is...",
				"scope": "rule",
				"title": "Task bundle references pinned to digest",
				"custom": {
					"depends_on": ["attestation_type.known_attestation_type"],
					"failure_msg": "Pipeline task '%s' uses an unpinned task bundle reference '%s'",
					"short_name": "task_ref_bundles_pinned",
					"solution": "Specify the task bundle reference with a full digest rather than a tag.",
				},
			},
			"location": {
				"file": "policy/release/attestation_task_bundle.rego",
				"row": 71,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal"],
					"depends_on": ["attestation_type.pipelinerun_attestation_found"],
					"failure_msg": "Unknown attestation type '%s'",
					"short_name": "known_attestation_type",
					"solution": "Make sure the \"_type\" field in the attestation is supported. Supported types are...",
				},
				"description": "A sanity check to confirm the attestation found for the image has a known...",
				"scope": "rule",
				"title": "Known attestation type found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 30,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal"],
					"failure_msg": "Missing pipelinerun attestation",
					"short_name": "pipelinerun_attestation_found",
					"solution": "Make sure the attestation being verified was generated from a Tekton pipelineRun.",
				},
				"description": "Confirm at least one PipelineRun attestation is present.",
				"scope": "rule",
				"title": "PipelineRun attestation found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 49,
				"col": 1,
			},
		},
	],
}

test_required_annotations_valid if {
	lib.assert_empty(checks.violation) with input as opa_inspect_valid
}

opa_inspect_missing_annotations := {
	"namespaces": {"data.attestation_task_bundle": [
		"policy/release/attestation_task_bundle.rego",
		"policy/release/attestation_task_bundle_test.rego",
	]},
	"annotations": [{
		"annotations": {
			"scope": "rule",
			"description": "Check for the existence of a task bundle. This rule will fail if the task is not called...",
			"custom": {
				"flagiure_msg": "Task '%s' does not contain a bundle reference",
				"short_name": "disallowed_task_reference",
			},
		},
		"location": {
			"file": "policy/release/attestation_task_bundle.rego",
			"row": 13,
			"col": 1,
		},
	}],
}

opa_inspect_missing_dependency := {
	"namespaces": {"data.attestation_task_bundle": [
		"policy/release/attestation_task_bundle.rego",
		"policy/release/attestation_task_bundle_test.rego",
	]},
	"annotations": [{
		"annotations": {
			"description": "Check if the Tekton Bundle used for the Tasks in the Pipeline definition is pinned to...",
			"scope": "rule",
			"title": "Task bundle references pinned to digest",
			"custom": {
				"depends_on": ["attestation_type.known_attestation_type"],
				"failure_msg": "Pipeline task '%s' uses an unpinned task bundle reference '%s'",
				"short_name": "task_ref_bundles_pinned",
				"solution": "Specify the task bundle reference with a full digest rather than a tag.",
			},
		},
		"location": {
			"file": "policy/release/attestation_task_bundle.rego",
			"row": 71,
			"col": 1,
		},
	}],
}

opa_inspect_duplicate := {
	"namespaces": {"data.attestation_type": ["policy/release/attestation_type.rego"]},
	"annotations": [
		{
			"annotations": {
				"custom": {
					"collections": ["minimal"],
					"failure_msg": "Unknown attestation type '%s'",
					"short_name": "known_attestation_type",
					"solution": "Make sure the \"_type\" field in the attestation is supported. Supported types are...",
				},
				"description": "A sanity check to confirm the attestation found for the image has a known...",
				"scope": "rule",
				"title": "Known attestation type found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 30,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal"],
					"failure_msg": "Unknown attestation type '%s'",
					"short_name": "known_attestation_type",
					"solution": "Make sure the \"_type\" field in the attestation is supported. Supported types are...",
				},
				"description": "A sanity check to confirm the attestation found for the image has a known...",
				"scope": "rule",
				"title": "Known attestation type found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 50,
				"col": 1,
			},
		},
	],
}

opa_inspect_effective_on := {
	"namespaces": {"data.effective_on": ["policy/release/effective_on.rego"]},
	"annotations": [
		{
			"annotations": {
				"custom": {
					"short_name": "good_effective_on",
					"failure_msg": "all good",
					"effective_on": "1985-04-12T23:20:50.52Z",
				},
				"description": "effective_on must be well formed",
				"scope": "rule",
				"title": "effective_on ok case",
			},
			"location": {
				"file": "policy/release/effective_on.rego",
				"row": 1,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"short_name": "bad_effective_on",
					"failure_msg": "not good",
					"effective_on": "wubba lubba dub dub",
				},
				"description": "effective_on must be well formed",
				"scope": "rule",
				"title": "effective_on bad case",
			},
			"location": {
				"file": "policy/release/effective_on.rego",
				"row": 10,
				"col": 1,
			},
		},
	],
}

test_required_annotations_invalid if {
	err = "ERROR: Missing annotation(s) custom.failure_msg, title at policy/release/attestation_task_bundle.rego:13"
	lib.assert_equal({err}, checks.violation) with input as opa_inspect_missing_annotations
}

test_missing_dependency_invalid if {
	err = `ERROR: Missing dependency rule "data.attestation_type.known_attestation_type" at policy/release/attestation_task_bundle.rego:71`
	lib.assert_equal({err}, checks.violation) with input as opa_inspect_missing_dependency
}

test_duplicate_rules if {
	err1 = `ERROR: Found non-unique code "data.attestation_type.known_attestation_type" at policy/release/attestation_type.rego:30`

	err2 = `ERROR: Found non-unique code "data.attestation_type.known_attestation_type" at policy/release/attestation_type.rego:50`
	lib.assert_equal({err1, err2}, checks.violation) with input as opa_inspect_duplicate
}

test_effective_on if {
	err := `ERROR: wrong syntax of effective_on value "wubba lubba dub dub" at policy/release/effective_on.rego:10`
	lib.assert_equal({err}, checks.violation) with input as opa_inspect_effective_on
}

opa_inspect_collection_mismatch := {
	"namespaces": {
		"data.attestation_type": ["policy/release/attestation_type.rego"],
		"data.tasks": ["policy/release/tasks.rego"],
	},
	"annotations": [
		{
			"annotations": {
				"custom": {
					"collections": ["minimal", "redhat"],
					"short_name": "pipelinerun_attestation_found",
					"failure_msg": "Missing pipelinerun attestation",
				},
				"description": "Confirm at least one PipelineRun attestation is present.",
				"scope": "rule",
				"title": "PipelineRun attestation found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 60,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal", "redhat", "slsa3"],
					"depends_on": ["attestation_type.pipelinerun_attestation_found"],
					"short_name": "pipeline_has_tasks",
					"failure_msg": "No tasks found",
				},
				"description": "Ensure that at least one Task is present in the PipelineRun attestation.",
				"scope": "rule",
				"title": "Pipeline run includes at least one task",
			},
			"location": {
				"file": "policy/release/tasks.rego",
				"row": 30,
				"col": 1,
			},
		},
	],
}

test_dependency_collection_mismatch if {
	# regal ignore:line-length
	err := `ERROR: Dependency "attestation_type.pipelinerun_attestation_found" is missing from collections ["slsa3"] (required by rule at policy/release/tasks.rego:30 which is in collections ["minimal", "redhat", "slsa3"])`
	lib.assert_equal({err}, checks.violation) with input as opa_inspect_collection_mismatch
}

opa_inspect_collection_valid := {
	"namespaces": {
		"data.attestation_type": ["policy/release/attestation_type.rego"],
		"data.tasks": ["policy/release/tasks.rego"],
	},
	"annotations": [
		{
			"annotations": {
				"custom": {
					"collections": ["minimal", "redhat", "slsa3"],
					"short_name": "pipelinerun_attestation_found",
					"failure_msg": "Missing pipelinerun attestation",
				},
				"description": "Confirm at least one PipelineRun attestation is present.",
				"scope": "rule",
				"title": "PipelineRun attestation found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 60,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal", "redhat", "slsa3"],
					"depends_on": ["attestation_type.pipelinerun_attestation_found"],
					"short_name": "pipeline_has_tasks",
					"failure_msg": "No tasks found",
				},
				"description": "Ensure that at least one Task is present in the PipelineRun attestation.",
				"scope": "rule",
				"title": "Pipeline run includes at least one task",
			},
			"location": {
				"file": "policy/release/tasks.rego",
				"row": 30,
				"col": 1,
			},
		},
	],
}

test_dependency_collection_valid if {
	lib.assert_empty(checks.violation) with input as opa_inspect_collection_valid
}

opa_inspect_dependency_no_collections := {
	"namespaces": {
		"data.attestation_type": ["policy/release/attestation_type.rego"],
		"data.tasks": ["policy/release/tasks.rego"],
	},
	"annotations": [
		{
			"annotations": {
				"custom": {
					"short_name": "pipelinerun_attestation_found",
					"failure_msg": "Missing pipelinerun attestation",
				},
				"description": "Confirm at least one PipelineRun attestation is present.",
				"scope": "rule",
				"title": "PipelineRun attestation found",
			},
			"location": {
				"file": "policy/release/attestation_type.rego",
				"row": 60,
				"col": 1,
			},
		},
		{
			"annotations": {
				"custom": {
					"collections": ["minimal", "redhat", "slsa3"],
					"depends_on": ["attestation_type.pipelinerun_attestation_found"],
					"short_name": "pipeline_has_tasks",
					"failure_msg": "No tasks found",
				},
				"description": "Ensure that at least one Task is present in the PipelineRun attestation.",
				"scope": "rule",
				"title": "Pipeline run includes at least one task",
			},
			"location": {
				"file": "policy/release/tasks.rego",
				"row": 30,
				"col": 1,
			},
		},
	],
}

test_dependency_no_collections if {
	# When a dependent rule has collections but its dependency lacks collections entirely,
	# the dependency should be considered missing from all the dependent's collections
	# regal ignore:line-length
	err := `ERROR: Dependency "attestation_type.pipelinerun_attestation_found" is missing from collections ["minimal", "redhat", "slsa3"] (required by rule at policy/release/tasks.rego:30 which is in collections ["minimal", "redhat", "slsa3"])`
	lib.assert_equal({err}, checks.violation) with input as opa_inspect_dependency_no_collections
}

test_policy_rule_files_includes_policy_directory if {
	namespaces := {"data.policy.release.tasks": [
		"policy/release/tasks.rego",
		"policy/release/tasks_test.rego",
	]}

	result := checks.policy_rule_files(namespaces)
	expected := {{
		"namespace": "data.policy.release.tasks",
		"files": {"policy/release/tasks.rego"},
	}}

	lib.assert_equal(expected, result)
}

test_policy_rule_files_excludes_lib_directory if {
	namespaces := {
		"data.policy.lib.utils": [
			"policy/lib/utils.rego",
			"policy/lib/utils_test.rego",
		],
		"data.policy.release.lib": [
			"policy/release/lib/utils.rego",
			"policy/release/lib/utils_test.rego",
		],
	}

	result := checks.policy_rule_files(namespaces)
	lib.assert_empty(result)
}

test_policy_rule_files_excludes_non_policy_directory if {
	namespaces := {
		"data.checks": ["checks/annotations.rego"],
		"data.other": ["other/file.rego"],
	}

	result := checks.policy_rule_files(namespaces)
	lib.assert_empty(result)
}
