package checks_test

import rego.v1

import data.checks
import data.lib.utils as lib

opa_inspect_valid := {
	"namespaces": {
		"data.policy.release.attestation_task_bundle": ["policy/release/attestation_task_bundle.rego"],
		"data.policy.release.attestation_type": ["policy/release/attestation_type.rego"],
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
	"namespaces": {"data.policy.release.attestation_task_bundle": [
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
	"namespaces": {"data.policy.release.attestation_task_bundle": [
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
	"namespaces": {"data.policy.release.attestation_type": ["policy/release/attestation_type.rego"]},
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
	"namespaces": {"data.policy.release.effective_on": ["policy/release/effective_on.rego"]},
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
	# regal ignore:line-length
	err = `ERROR: Missing dependency rule "data.policy.release.attestation_type.known_attestation_type" at policy/release/attestation_task_bundle.rego:71`
	lib.assert_equal({err}, checks.violation) with input as opa_inspect_missing_dependency
}

test_duplicate_rules if {
	# regal ignore:line-length
	err1 = `ERROR: Found non-unique code "data.policy.release.attestation_type.known_attestation_type" at policy/release/attestation_type.rego:30`

	# regal ignore:line-length
	err2 = `ERROR: Found non-unique code "data.policy.release.attestation_type.known_attestation_type" at policy/release/attestation_type.rego:50`
	lib.assert_equal({err1, err2}, checks.violation) with input as opa_inspect_duplicate
}

test_effective_on if {
	err := `ERROR: wrong syntax of effective_on value "wubba lubba dub dub" at policy/release/effective_on.rego:10`
	lib.assert_equal({err}, checks.violation) with input as opa_inspect_effective_on
}
