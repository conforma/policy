package lib_test

import future.keywords.in

import data.lib
import data.lib.bundles_test
import data.lib.tkn_test
import data.lib_test

pr_build_type := "tekton.dev/v1beta1/PipelineRun"

pr_build_type_legacy := "https://tekton.dev/attestations/chains/pipelinerun@v2"

tr_build_type := "tekton.dev/v1beta1/TaskRun"

tr_build_type_legacy := "https://tekton.dev/attestations/chains@v2"

mock_pr_att := {"statement": {"predicate": {"buildType": pr_build_type}}}

mock_pr_att_legacy := {"statement": {"predicate": {"buildType": pr_build_type_legacy}}}

mock_tr_att := {"statement": {"predicate": {"buildType": tr_build_type}}}

mock_tr_att_legacy := {"statement": {"predicate": {"buildType": tr_build_type_legacy}}}

garbage_att := {"statement": {"predicate": {"buildType": "garbage"}}}

valid_slsav1_att := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
		"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		"resolvedDependencies": [],
	}},
}}

# This is used through the tests to generate an attestation of a PipelineRun
# with an inline Task definition, look at using att_mock_helper_ref to generate
# an attestation with a Task referenced from a Tekton Bundle image
att_mock_helper(name, result_map, task_name) := att_mock_helper_ref(name, result_map, task_name, "")

_task_ref(task_name, bundle_ref) := r {
	bundle_ref != ""
	ref_data := {"kind": "Task", "name": task_name, "bundle": bundle_ref}
	r := {"ref": ref_data}
}

_task_ref(_, bundle_ref) := r {
	bundle_ref == ""
	r := {}
}

# This is used through the tests to generate an attestation of a PipelineRun
# with an Task definition loaded from a Tekton Bundle image provided via
# `bundle_ref`.
# Use:
# att_mock_helper_ref_plain_result(
#	"result_name", "result_value", "task_name", "registry.io/name:tag...")
# Make note of `bundle_data` and `acceptable_bundle_ref` in the data.lib.bundles
# package that helps setup the acceptable bundle, for example:
#
# import data.lib
# import data.lib.bundles
# attestations := [att_mock_helper_ref_plain_result(
#	"RESULT_NAME", "result_value", "task-name", bundles.acceptable_bundle_ref
# )]
# {...} == deny
#	with data["task-bundles"] as bundles.bundle_data
#	with input.attestations as attestations
#
# NOTE: In most cases, a task produces a result that is JSON encoded. When mocking results
# from such tasks, prefer the att_mock_helper_ref function instead.
att_mock_helper_ref_plain_result(name, result, task_name, bundle_ref) := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [object.union(
		{"name": task_name, "results": [{
			"name": name,
			"value": result,
		}]},
		_task_ref(task_name, bundle_ref),
	)]},
}}}

# This is used through the tests to generate an attestation of a PipelineRun
# with an Task definition loaded from a Tekton Bundle image provided via
# `bundle_ref`.
# Use:
# att_mock_helper_ref(
# 	"result_name", {"value1": 1, "value2", "b"}, "task_name", "registry.io/name:tag...")
# Make note of `bundle_data` and `acceptable_bundle_ref` in the data.lib.bundles
# package that helps setup the acceptable bundle, for example:
#
# import data.lib
# import data.lib.bundles
# attestations := [att_mock_helper_ref(
#	"RESULT_NAME", {...}, "task-name", bundles.acceptable_bundle_ref
# )]
# {...} == deny
#	with data["task-bundles"] as bundles.bundle_data
#	with input.attestations as attestations
#
# NOTE: If the task being mocked does not produced a JSON encoded result, use
# att_mock_helper_ref_plain_result instead.
att_mock_helper_ref(name, result, task_name, bundle_ref) := att_mock_helper_ref_plain_result(
	name,
	json.marshal(result),
	task_name,
	bundle_ref,
)

att_mock_task_helper(task) := [{"statement": {"predicate": {
	"buildConfig": {"tasks": [task]},
	"buildType": lib.tekton_pipeline_run,
}}}]

# make working with tasks and resolvedDeps easier
mock_slsav1_attestation_with_tasks(tasks) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": lib.tekton_slsav1_pipeline_run,
		"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		"resolvedDependencies": tkn_test.resolved_dependencies(tasks),
	}},
}}

mock_slsav1_attestation_bundles(bundles) := a {
	tasks := [task |
		some bundle in bundles
		task := tkn_test.slsav1_task_bundle("my-task", bundle)
	]
	a := mock_slsav1_attestation_with_tasks(tasks)
}

mock_slsav02_attestation_bundles(bundles) := a {
	tasks := [task |
		some index, bundle in bundles
		task := {
			"name": sprintf("task-run-%d", [index]),
			"ref": {
				"name": "my-task",
				"bundle": bundle,
			},
		}
	]

	a := {"statement": {"predicate": {
		"buildConfig": {"tasks": tasks},
		"buildType": lib.tekton_pipeline_run,
	}}}
}

test_tasks_from_pipelinerun {
	slsa1_task := tkn_test.slsav1_task("buildah")
	slsa1_att := [json.patch(valid_slsav1_att, [{
		"op": "replace",
		"path": "/statement/predicate/buildDefinition/resolvedDependencies",
		"value": tkn_test.resolved_dependencies([slsa1_task]),
	}])]
	lib.assert_equal([slsa1_task], lib.tasks_from_pipelinerun) with input.attestations as slsa1_att

	slsa02_task := {"name": "my-task", "ref": {"kind": "task"}}
	slsa02_att := att_mock_task_helper(slsa02_task)
	lib.assert_equal([slsa02_task], lib.tasks_from_pipelinerun) with input.attestations as slsa02_att
}

test_pr_attestations {
	lib.assert_equal(
		[mock_pr_att.statement, mock_pr_att_legacy.statement],
		lib.pipelinerun_attestations,
	) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		mock_pr_att,
		mock_pr_att_legacy,
		garbage_att,
	]

	# Deprecate format should still work for now
	lib.assert_equal(
		[mock_pr_att.statement, mock_pr_att_legacy.statement],
		lib.pipelinerun_attestations,
	) with input.attestations as [
		mock_tr_att.statement,
		mock_tr_att_legacy.statement,
		mock_pr_att.statement,
		mock_pr_att_legacy.statement,
		garbage_att.statement,
	]

	lib.assert_equal([], lib.pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		garbage_att,
	]
}

# regal ignore:rule-length
test_pipelinerun_slsa_provenance_v1 {
	provenance_with_pr_spec := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		}},
	}}
	provenance_with_pr_ref := json.patch(provenance_with_pr_spec, [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/externalParameters/runSpec",
		"value": {"pipelineRef": {}},
	}])

	attestations := [
		provenance_with_pr_spec,
		provenance_with_pr_ref,
		json.patch(provenance_with_pr_spec, [{
			"op": "add",
			"path": "/statement/predicateType", "value": "https://slsa.dev/provenance/v0.2",
		}]),
		json.patch(provenance_with_pr_spec, [{"op": "add", "path": "/statement/predicate", "value": {}}]),
		json.patch(provenance_with_pr_spec, [{
			"op": "add",
			"path": "/statement/predicate/buildDefinition",
			"value": {},
		}]),
		json.patch(provenance_with_pr_spec, [{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/buildType",
			"value": "https://tekton.dev/chains/v2/mambo",
		}]),
		json.patch(provenance_with_pr_spec, [{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/externalParameters",
			"value": {},
		}]),
		json.patch(provenance_with_pr_spec, [{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/externalParameters/runSpec",
			"value": {},
		}]),
		json.patch(provenance_with_pr_spec, [{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/externalParameters/runSpec",
			"value": {"taskRef": {}},
		}]),
	]
	expected := [provenance_with_pr_spec.statement, provenance_with_pr_ref.statement]
	lib.assert_equal(expected, lib.pipelinerun_slsa_provenance_v1) with input.attestations as attestations

	# Deprecated format should still work for now
	old_attestations := [att.statement | some att in attestations]
	lib.assert_equal(expected, lib.pipelinerun_slsa_provenance_v1) with input.attestations as old_attestations
}

test_tr_attestations {
	lib.assert_equal([mock_tr_att.statement], lib.taskrun_attestations) with input.attestations as [
		mock_tr_att,
		mock_pr_att,
		garbage_att,
	]

	# Deprecated format should still work for now
	lib.assert_equal([mock_tr_att.statement], lib.taskrun_attestations) with input.attestations as [
		mock_tr_att.statement,
		mock_pr_att.statement,
		garbage_att.statement,
	]

	lib.assert_equal([], lib.taskrun_attestations) with input.attestations as [mock_pr_att, garbage_att]
}

test_att_mock_helper {
	expected := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{"name": "mytask", "results": [{
			"name": "result-name",
			"value": "{\"foo\":\"bar\"}",
		}]}]},
	}}}

	lib.assert_equal(expected, att_mock_helper("result-name", {"foo": "bar"}, "mytask"))
}

test_att_mock_helper_ref {
	expected := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": "mytask",
			"ref": {
				"name": "mytask",
				"kind": "Task",
				"bundle": "registry.img/name:tag@sha256:digest",
			},
			"results": [{
				"name": "result-name",
				"value": "{\"foo\":\"bar\"}",
			}],
		}]},
	}}}

	lib.assert_equal(expected, att_mock_helper_ref(
		"result-name",
		{"foo": "bar"},
		"mytask",
		"registry.img/name:tag@sha256:digest",
	))
}

test_results_from_tests {
	lib.assert_equal("TEST_OUTPUT", lib.task_test_result_name)

	expected := {
		"value": {"result": "SUCCESS", "foo": "bar"},
		"name": "mytask",
		"bundle": "registry.img/acceptable@sha256:digest",
	}

	att1 = lib_test.att_mock_helper_ref(
		lib.task_test_result_name, {
			"result": "SUCCESS",
			"foo": "bar",
		},
		"mytask", bundles_test.acceptable_bundle_ref,
	)
	lib.assert_equal([expected], lib.results_from_tests) with input.attestations as [att1]

	# An edge case that may never happen
	att2 = lib_test.att_mock_helper_ref(
		lib.task_test_result_name, {
			"result": "SUCCESS",
			"foo": "bar",
		},
		"mytask", bundles_test.acceptable_bundle_ref,
	)
	lib.assert_equal([expected], lib.results_from_tests) with input.attestations as [att2]

	att3 := mock_slsav1_attestation_with_tasks([tkn_test.slsav1_task_bundle(
		tkn_test.slsav1_task_result(
			"mytask",
			[{
				"name": lib.task_test_result_name,
				"type": "string",
				"value": json.marshal({"result": "SUCCESS", "foo": "bar"}),
			}],
		),
		bundles_test.acceptable_bundle_ref,
	)])
	lib.assert_equal([expected], lib.results_from_tests) with input.attestations as [att3]
}

test_task_not_in_pipelinerun {
	task_name := "bad-task"
	d := att_mock_task_helper({"name": "my-task", "ref": {"kind": "task"}})

	not lib.task_in_pipelinerun(task_name) with input.attestations as d
}

test_result_in_task {
	task_name := "my-task"
	result_name := "IMAGE"
	d := att_mock_task_helper({
		"name": task_name,
		"results": [{
			"name": result_name,
			"value": "result value",
		}],
		"ref": {"kind": "task"},
	})

	lib.result_in_task(task_name, result_name) with input.attestations as d
}

test_result_not_in_task {
	task_name := "my-task"
	result_name := "BAD-RESULT"
	d := att_mock_task_helper({
		"name": task_name,
		"results": [{
			"name": "result name",
			"value": "result value",
		}],
		"ref": {"kind": "task"},
	})

	not lib.result_in_task(task_name, result_name) with input.attestations as d
}

test_task_succeeded {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Succeeded",
		"ref": {"kind": "task"},
	})

	lib.task_succeeded(task_name) with input.attestations as d
}

test_task_not_succeeded {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Failed",
		"ref": {"kind": "task"},
	})

	not lib.task_succeeded(task_name) with input.attestations as d
}

test_unmarshall_json {
	lib.assert_equal({"a": 1, "b": "c"}, lib.unmarshal("{\"a\":1,\"b\":\"c\"}"))
	lib.assert_equal("not JSON", lib.unmarshal("not JSON"))
	lib.assert_equal("", lib.unmarshal(""))
}
