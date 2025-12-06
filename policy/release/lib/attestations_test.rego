package lib_test

import rego.v1

import data.lib
import data.lib.tekton_test

pr_build_type := "tekton.dev/v1beta1/PipelineRun"

pr_build_type_legacy := "https://tekton.dev/attestations/chains/pipelinerun@v2"

tr_build_type := "tekton.dev/v1beta1/TaskRun"

tr_build_type_legacy := "https://tekton.dev/attestations/chains@v2"

mock_pr_att := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildType": pr_build_type},
}}

mock_pr_att_legacy := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {"buildType": pr_build_type_legacy},
}}

mock_tr_att := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildType": tr_build_type},
}}

mock_tr_att_legacy := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {"buildType": tr_build_type_legacy},
}}

garbage_att := {"statement": {
	"predicateType": "https://oscar.sesame/v1",
	"predicate": {"buildType": "garbage"},
}}

trusted_bundle_ref := "registry.img/acceptable@sha256:digest"

# This is used through the tests to generate an attestation of a PipelineRun
# with an inline Task definition, look at using att_mock_helper_ref to generate
# an attestation with a Task referenced from a Tekton Bundle image
att_mock_helper(name, result_map, task_name) := att_mock_helper_ref(name, result_map, task_name, "")

_task_ref(task_name, bundle_ref) := r if {
	bundle_ref != ""
	ref_data := {"kind": "Task", "name": task_name, "bundle": bundle_ref}
	r := {"ref": ref_data}
}

_task_ref(_, bundle_ref) := r if {
	bundle_ref == ""
	r := {}
}

# This is used through the tests to generate an attestation of a PipelineRun
# with an Task definition loaded from a Tekton Bundle image provided via
# `bundle_ref`.
# Use:
# att_mock_helper_ref_plain_result(
#	"result_name", "result_value", "task_name", "registry.io/name:tag...")
#
# NOTE: In most cases, a task produces a result that is JSON encoded. When mocking results
# from such tasks, prefer the att_mock_helper_ref function instead.
att_mock_helper_ref_plain_result(name, result, task_name, bundle_ref) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [object.union(
			{"name": task_name, "results": [{
				"name": name,
				"value": result,
			}]},
			_task_ref(task_name, bundle_ref),
		)]},
	},
}}

# This is used through the tests to generate an attestation of a PipelineRun
# with an Task definition loaded from a Tekton Bundle image provided via
# `bundle_ref`.
# Use:
# att_mock_helper_ref(
# 	"result_name", {"value1": 1, "value2", "b"}, "task_name", "registry.io/name:tag...")
#
# NOTE: If the task being mocked does not produced a JSON encoded result, use
# att_mock_helper_ref_plain_result instead.
att_mock_helper_ref(name, result, task_name, bundle_ref) := att_mock_helper_ref_plain_result(
	name,
	json.marshal(result),
	task_name,
	bundle_ref,
)

att_mock_task_helper(task) := [{"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildConfig": {"tasks": [task]},
		"buildType": lib.tekton_pipeline_run,
	},
}}]

test_tasks_from_pipelinerun if {
	slsa1_task := tekton_test.slsav1_task("buildah")
	slsa1_att := tekton_test.slsav1_attestation([slsa1_task])
	_resolved_task_base := tekton_test.resolved_slsav1_task("buildah", [], [])
	resolved_task := json.remove(_resolved_task_base, ["/params"])
	lib.assert_equal([resolved_task], lib.tasks_from_pipelinerun) with input.attestations as [slsa1_att]

	slsa02_task := {"name": "my-task", "ref": {"kind": "task"}}
	slsa02_att := att_mock_task_helper(slsa02_task)
	resolved_slsa02_task := {"name": "my-task", "ref": {"kind": "task"}}
	lib.assert_equal([resolved_slsa02_task], lib.tasks_from_pipelinerun) with input.attestations as slsa02_att
}

test_slsa_provenance_attestations if {
	lib.assert_equal(lib.slsa_provenance_attestations, []) with input.attestations as []

	attestations := [
		mock_pr_att,
		mock_pr_att_legacy,
		mock_tr_att,
		mock_tr_att_legacy,
		garbage_att,
	]
	expected := [
		mock_pr_att,
		mock_pr_att_legacy,
		mock_tr_att,
		mock_tr_att_legacy,
	]
	lib.assert_equal(lib.slsa_provenance_attestations, expected) with input.attestations as attestations
}

test_pr_attestations_v1 if {
	# Test v1.0 PipelineRun attestation
	lib.assert_equal([mock_pr_att], lib.pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_pr_att,
		garbage_att,
	]
}

test_pr_attestations_v02 if {
	# Test v0.2 PipelineRun attestation
	lib.assert_equal([mock_pr_att_legacy], lib.pipelinerun_attestations) with input.attestations as [
		mock_tr_att_legacy,
		mock_pr_att_legacy,
		garbage_att,
	]
}

test_pr_attestations_both if {
	# Test both v0.2 and v1.0 PipelineRun attestations together
	# Use properly structured v1.0 attestation
	v1_att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		}},
	}}
	lib.assert_equal(
		[mock_pr_att_legacy, v1_att],
		lib.pipelinerun_attestations,
	) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		v1_att,
		mock_pr_att_legacy,
		garbage_att,
	]
}

test_pr_attestations_empty if {
	# Test that no PipelineRun attestations returns empty list
	lib.assert_equal([], lib.pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_tr_att_legacy,
		garbage_att,
	]
}

# regal ignore:rule-length
test_pipelinerun_slsa_provenance_v1 if {
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
	expected := [provenance_with_pr_spec, provenance_with_pr_ref]
	lib.assert_equal(expected, lib.pipelinerun_slsa_provenance_v1) with input.attestations as attestations
}

test_tr_attestations if {
	lib.assert_equal([mock_tr_att], lib.taskrun_attestations) with input.attestations as [
		mock_tr_att,
		mock_pr_att,
		garbage_att,
	]

	lib.assert_equal([], lib.taskrun_attestations) with input.attestations as [mock_pr_att, garbage_att]
}

test_att_mock_helper if {
	expected := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"name": "mytask", "results": [{
				"name": "result-name",
				"value": "{\"foo\":\"bar\"}",
			}]}]},
		},
	}}

	lib.assert_equal(expected, att_mock_helper("result-name", {"foo": "bar"}, "mytask"))
}

test_att_mock_helper_ref if {
	expected := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
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
		},
	}}

	lib.assert_equal(expected, att_mock_helper_ref(
		"result-name",
		{"foo": "bar"},
		"mytask",
		"registry.img/name:tag@sha256:digest",
	))
}

test_results_from_tests if {
	lib.assert_equal("TEST_OUTPUT", lib.task_test_result_name)

	expected := {
		"value": {"result": "SUCCESS", "foo": "bar"},
		"name": "mytask",
		"bundle": "registry.img/acceptable@sha256:digest",
	}

	att1 := att_mock_helper_ref(
		lib.task_test_result_name, {
			"result": "SUCCESS",
			"foo": "bar",
		},
		"mytask", trusted_bundle_ref,
	)
	lib.assert_equal([expected], lib.results_from_tests) with input.attestations as [att1]

	# An edge case that may never happen
	att2 := att_mock_helper_ref(
		lib.task_test_result_name, {
			"result": "SUCCESS",
			"foo": "bar",
		},
		"mytask", trusted_bundle_ref,
	)
	lib.assert_equal([expected], lib.results_from_tests) with input.attestations as [att2]

	task3_base := tekton_test.resolved_slsav1_task(
		"mytask",
		[],
		[{
			"name": lib.task_test_result_name,
			"value": {"result": "SUCCESS", "foo": "bar"},
		}],
	)
	task3 = tekton_test.with_bundle(task3_base, trusted_bundle_ref)

	att3 := tekton_test.slsav1_attestation([task3])
	lib.assert_equal([expected], lib.results_from_tests) with input.attestations as [att3]
}

test_task_not_in_pipelinerun if {
	task_name := "bad-task"
	d := att_mock_task_helper({"name": "my-task", "ref": {"kind": "task"}})

	not lib.task_in_pipelinerun(task_name) with input.attestations as d
}

test_result_in_task if {
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

test_result_not_in_task if {
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

test_task_succeeded if {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Succeeded",
		"ref": {"kind": "task"},
	})

	lib.task_succeeded(task_name) with input.attestations as d
}

test_task_not_succeeded if {
	task_name := "my-task"
	d := att_mock_task_helper({
		"name": task_name,
		"status": "Failed",
		"ref": {"kind": "task"},
	})

	not lib.task_succeeded(task_name) with input.attestations as d
}

test_unmarshall_json if {
	lib.assert_equal({"a": 1, "b": "c"}, lib.unmarshal("{\"a\":1,\"b\":\"c\"}"))
	lib.assert_equal("not JSON", lib.unmarshal("not JSON"))
	lib.assert_equal("", lib.unmarshal(""))
}

test_param_values if {
	lib.assert_equal(lib.param_values("spam"), {"spam"})
	lib.assert_equal(lib.param_values(["spam", "eggs"]), {"spam", "eggs"})
	lib.assert_equal(lib.param_values({"maps": "spam", "sgge": "eggs"}), {"spam", "eggs"})

	not lib.param_values(123)
}

test_result_values if {
	lib.assert_equal(lib.result_values({"type": "string", "value": "spam"}), {"spam"})
	lib.assert_equal(lib.result_values({"type": "array", "value": ["spam", "eggs"]}), {"spam", "eggs"})
	lib.assert_equal(lib.result_values({"type": "object", "value": {"maps": "spam", "sgge": "eggs"}}), {"spam", "eggs"})

	not lib.result_values(123)
}

# Helper to create a build task (has IMAGE_URL and IMAGE_DIGEST)
_build_task := {
	"name": "buildah",
	"ref": {"kind": "Task", "name": "buildah", "bundle": trusted_bundle_ref},
	"results": [
		{"name": "IMAGE_URL", "value": "quay.io/test/image:tag"},
		{"name": "IMAGE_DIGEST", "value": "sha256:abc123"},
	],
}

# Helper to create a non-build task (no IMAGE_URL/IMAGE_DIGEST)
_non_build_task := {
	"name": "git-clone",
	"ref": {"kind": "Task", "name": "git-clone", "bundle": trusted_bundle_ref},
	"results": [
		{"name": "url", "value": "https://github.com/test/repo"},
		{"name": "commit", "value": "abc123"},
	],
}

# Helper to create SLSA v0.2 attestation with metadata
_attestation_v02_with_metadata(build_finished_on, tasks) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": tasks},
		"metadata": {
			"buildFinishedOn": build_finished_on,
			"buildStartedOn": "2025-01-01T00:00:00Z",
		},
	},
}}

# Helper to create SLSA v1.0 attestation with metadata
_attestation_v1_with_metadata(build_finished_on, tasks) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": tekton_test.resolved_dependencies(tasks),
		},
		"runDetails": {"metadata": {
			"buildFinishedOn": build_finished_on,
			"buildStartedOn": "2025-01-01T00:00:00Z",
		}},
	},
}}

test_pipelinerun_attestations_single_v02 if {
	# Test single v0.2 attestation
	att := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	expected := [att]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as [att]
}

test_pipelinerun_attestations_multiple_v02_latest_first if {
	# Multiple v0.2 attestations, latest is first in list
	att1 := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	att2 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	attestations := [att1, att2]
	expected := [att1]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_multiple_v02_latest_last if {
	# Multiple v0.2 attestations, latest is last in list
	att1 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	att2 := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	attestations := [att1, att2]
	expected := [att2]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_multiple_v02_middle if {
	# Multiple v0.2 attestations, latest is in the middle
	att1 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	att2 := _attestation_v02_with_metadata("2025-01-25T20:00:00Z", [_build_task])
	att3 := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	attestations := [att1, att2, att3]
	expected := [att2]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_multiple_v02_missing_timestamp if {
	# Multiple v0.2 attestations where at least one doesn't have a timestamp - should return empty
	att_with_metadata := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	att_without_metadata := json.patch(
		_attestation_v02_with_metadata("2025-01-25T20:00:00Z", [_build_task]),
		[{"op": "remove", "path": "/statement/predicate/metadata"}],
	)
	attestations := [att_with_metadata, att_without_metadata]
	expected := []
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_multiple_v1_missing_timestamp if {
	# Multiple v1.0 attestations where at least one doesn't have a timestamp - should return empty
	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_results := tekton_test.with_results(
		_task_base,
		[
			{"name": "IMAGE_URL", "type": "string", "value": "quay.io/test/image:tag"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc123"},
		],
	)
	v1_task := tekton_test.with_bundle(_task_w_results, trusted_bundle_ref)
	att_with_metadata := _attestation_v1_with_metadata("2025-01-20T15:45:00Z", [v1_task])
	att_without_metadata := json.patch(
		_attestation_v1_with_metadata("2025-01-25T20:00:00Z", [v1_task]),
		[{"op": "remove", "path": "/statement/predicate/runDetails"}],
	)
	attestations := [att_with_metadata, att_without_metadata]
	expected := []
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_mixed_formats if {
	# Test with both v0.2 and v1.0 attestations - should return both (one per type)
	v02_task := _build_task
	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_results := tekton_test.with_results(
		_task_base,
		[
			{"name": "IMAGE_URL", "type": "string", "value": "quay.io/test/image:tag"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc123"},
		],
	)
	v1_task := tekton_test.with_bundle(
		_task_w_results,
		trusted_bundle_ref,
	)
	att_v02 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [v02_task])
	att_v1 := _attestation_v1_with_metadata("2025-01-20T15:45:00Z", [v1_task])
	attestations := [att_v02, att_v1]
	expected := [att_v02, att_v1]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_empty if {
	# No attestations should return empty list
	expected := []
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as []
}

test_pipelinerun_attestations_single_no_timestamp if {
	# Single attestation without timestamp should still be returned
	att := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_non_build_task])
	expected := [att]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as [att]
}

test_pipelinerun_attestations_multiple_per_type if {
	# Test scenario: 3 attestations where 2 are v0.2 and 1 is v1.0
	# Should return the latest v0.2 and the v1.0
	v02_att1 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	v02_att2 := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	v1_att := _attestation_v1_with_metadata("2025-01-18T12:00:00Z", [_build_task])
	attestations := [v02_att1, v02_att2, v1_att]

	# Should return latest v0.2 (v02_att2) and the v1.0 (v1_att)
	expected := [v02_att2, v1_att]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_v1_multiple if {
	# Test multiple v1.0 attestations - should return the latest
	v1_att1 := _attestation_v1_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	v1_att2 := _attestation_v1_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	attestations := [v1_att1, v1_att2]
	expected := [v1_att2]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_v1_single_no_timestamp if {
	# Test single v1.0 attestation without timestamp - should still return it
	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_results := tekton_test.with_results(
		_task_base,
		[
			{"name": "IMAGE_URL", "type": "string", "value": "quay.io/test/image:tag"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc123"},
		],
	)
	v1_task := tekton_test.with_bundle(_task_w_results, trusted_bundle_ref)

	# Create v1.0 attestation without runDetails.metadata.buildFinishedOn
	v1_att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": tekton_test.resolved_dependencies([v1_task]),
		}},
	}}
	expected := [v1_att]
	lib.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as [v1_att]
}
