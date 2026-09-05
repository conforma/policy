package lib_test

import rego.v1

import data.lib
import data.lib.assertions
import data.lib.intoto
import data.lib.tekton
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

trusted_bundle_ref := "registry.img/acceptable@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"

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
	assertions.assert_equal([resolved_task], lib.tasks_from_pipelinerun) with input.attestations as [slsa1_att]

	slsa02_task := {"name": "my-task", "ref": {"kind": "task"}}
	slsa02_att := att_mock_task_helper(slsa02_task)
	resolved_slsa02_task := {"name": "my-task", "ref": {"kind": "task"}}
	assertions.assert_equal([resolved_slsa02_task], lib.tasks_from_pipelinerun) with input.attestations as slsa02_att
}

_default_test_timestamp := "2026-01-01T00:00:00Z"

_matching_test_statement_at(name, timestamp) := {
	"_type": "https://in-toto.io/Statement/v1",
	"predicateType": intoto.predicate_test_result,
	"subject": [{"name": "registry.io/repo/image", "digest": {"sha256": "abc123"}}],
	"predicate": {
		"configuration": [{"name": name}],
		"timestamp": timestamp,
	},
}

_matching_test_statement(name) := _matching_test_statement_at(name, _default_test_timestamp)

_verified_statement_provenance(name, provenance) := {
	"statement": _matching_test_statement(name),
	"provenance": provenance,
}

_task_names(tasks) := {name |
	some task in tasks
	name := tekton.task_name(task)
}

test_tasks_from_attestations_reuses_tekton_normalization if {
	v1_task := tekton_test.slsav1_task("clair-scan")
	v1_att := tekton_test.slsav1_attestation([v1_task])
	lib.is_pipelinerun_attestation(v1_att)
	v02_att := att_mock_task_helper({
		"name": "sast-snyk-check",
		"ref": {"kind": "task", "name": "sast-snyk-check"},
	})[0]
	lib.is_pipelinerun_attestation(v02_att)

	assertions.assert_equal(
		{"clair-scan", "sast-snyk-check"},
		_task_names(lib.tasks_from_attestations([v1_att, v02_att])),
	)
}

test_its_pipelinerun_attestations_retain_all_matching_pipelines if {
	clair_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("clair-scan")])
	sast_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("sast-snyk-check")])
	verified := {
		_verified_statement_provenance("clair-scan", clair_att),
		_verified_statement_provenance("sast-snyk-check", sast_att),
	}

	assertions.assert_equal(
		{clair_att, sast_att},
		lib.its_pipelinerun_attestations,
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as verified
		with intoto.verified_statement_provenances as verified

	assertions.assert_equal(
		{"clair-scan", "sast-snyk-check"},
		_task_names(lib.tasks_from_its_pipelineruns),
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as verified
		with intoto.verified_statement_provenances as verified

	assertions.assert_equal(
		{"clair-scan", "sast-snyk-check"},
		lib.its_pipelinerun_task_names,
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as verified
		with intoto.verified_statement_provenances as verified
}

test_its_pipelinerun_attestations_keep_latest_retry_per_integration_test if {
	unique_runs := {
		_verified_statement_provenance("integration-1", tekton_test.slsav1_attestation([tekton_test.slsav1_task("test-1")])),
		_verified_statement_provenance("integration-2", tekton_test.slsav1_attestation([tekton_test.slsav1_task("test-2")])),
		_verified_statement_provenance("integration-3", tekton_test.slsav1_attestation([tekton_test.slsav1_task("test-3")])),
		_verified_statement_provenance("integration-4", tekton_test.slsav1_attestation([tekton_test.slsav1_task("test-4")])),
	}
	retry_old := {
		"statement": _matching_test_statement_at("integration-5", "2026-01-01T01:00:00Z"),
		"provenance": tekton_test.slsav1_attestation([tekton_test.slsav1_task("retry-old")]),
	}
	retry_middle := {
		"statement": _matching_test_statement_at("integration-5", "2026-01-01T02:00:00Z"),
		"provenance": tekton_test.slsav1_attestation([tekton_test.slsav1_task("retry-middle")]),
	}
	retry_latest := {
		"statement": _matching_test_statement_at("integration-5", "2026-01-01T03:00:00Z"),
		"provenance": tekton_test.slsav1_attestation([tekton_test.slsav1_task("retry-latest")]),
	}
	associated := unique_runs | {retry_old, retry_middle, retry_latest}

	assertions.assert_equal(
		{"test-1", "test-2", "test-3", "test-4", "retry-latest"},
		_task_names(lib.tasks_from_associated_its_pipelineruns),
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated
}

test_its_pipelinerun_attestations_apply_trust_after_latest_retry_selection if {
	old_provenance := tekton_test.slsav1_attestation([tekton_test.slsav1_task("old-trusted")])
	latest_provenance := tekton_test.slsav1_attestation([tekton_test.slsav1_task("latest-untrusted")])
	old_run := {
		"statement": _matching_test_statement_at("retried-integration", "2026-01-01T01:00:00Z"),
		"provenance": old_provenance,
	}
	latest_run := {
		"statement": _matching_test_statement_at("retried-integration", "2026-01-01T02:00:00Z"),
		"provenance": latest_provenance,
	}
	associated := {old_run, latest_run}

	assertions.assert_equal(
		{latest_provenance},
		lib.associated_its_pipelinerun_attestations,
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated

	assertions.assert_empty(lib.its_pipelinerun_attestations) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated
		with intoto.verified_statement_provenances as {old_run}
}

test_its_pipelinerun_attestations_ignore_untrusted_older_retry if {
	old_provenance := tekton_test.slsav1_attestation([tekton_test.slsav1_task("old-untrusted")])
	latest_provenance := tekton_test.slsav1_attestation([tekton_test.slsav1_task("latest-trusted")])
	old_run := {
		"statement": _matching_test_statement_at("retried-integration", "2026-01-01T01:00:00Z"),
		"provenance": old_provenance,
	}
	latest_run := {
		"statement": _matching_test_statement_at("retried-integration", "2026-01-01T02:00:00Z"),
		"provenance": latest_provenance,
	}
	associated := {old_run, latest_run}

	assertions.assert_equal(
		{latest_provenance},
		lib.its_pipelinerun_attestations,
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated
		with intoto.verified_statement_provenances as {latest_run}
}

test_associated_its_pipelinerun_attestations_exclude_missing_test_identity if {
	provenance := tekton_test.slsav1_attestation([tekton_test.slsav1_task("unidentified-test")])
	statement := json.remove(_matching_test_statement("placeholder"), ["/predicate/configuration"])
	associated := {{"statement": statement, "provenance": provenance}}

	assertions.assert_empty(lib.associated_its_pipelinerun_attestations) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated
}

test_associated_its_pipelinerun_attestations_retain_verified_untrusted_candidates if {
	clair_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("clair-scan")])
	associated := {_verified_statement_provenance("clair-scan", clair_att)}

	assertions.assert_equal(
		{clair_att},
		lib.associated_its_pipelinerun_attestations,
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated

	assertions.assert_equal(
		{"clair-scan"},
		_task_names(lib.tasks_from_associated_its_pipelineruns),
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated
}

test_associated_its_pipelinerun_attestations_filter_unrelated_sources if {
	its_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("clair-scan")])
	taskrun_att := json.patch(its_att, [{
		"op": "replace",
		"path": "/statement/predicate/buildDefinition/buildType",
		"value": lib.tekton_task_run,
	}])
	wrong_subject := json.patch(_matching_test_statement("wrong-subject"), [{
		"op": "replace",
		"path": "/subject/0/digest/sha256",
		"value": "def456",
	}])
	non_test_statement := json.patch(_matching_test_statement("not-a-test-result"), [{
		"op": "replace",
		"path": "/predicateType",
		"value": intoto.predicate_vuln_scan,
	}])
	associated := {
		_verified_statement_provenance("clair-scan", its_att),
		{"statement": wrong_subject, "provenance": its_att},
		{"statement": non_test_statement, "provenance": its_att},
		_verified_statement_provenance("taskrun", taskrun_att),
	}

	assertions.assert_equal(
		{its_att},
		lib.associated_its_pipelinerun_attestations,
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated
}

test_its_pipelinerun_attestations_filter_unrelated_sources if {
	its_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("clair-scan")])
	taskrun_att := json.patch(its_att, [{
		"op": "replace",
		"path": "/statement/predicate/buildDefinition/buildType",
		"value": lib.tekton_task_run,
	}])
	wrong_subject := json.patch(_matching_test_statement("wrong-subject"), [{
		"op": "replace",
		"path": "/subject/0/digest/sha256",
		"value": "def456",
	}])
	non_test_statement := json.patch(_matching_test_statement("not-a-test-result"), [{
		"op": "replace",
		"path": "/predicateType",
		"value": intoto.predicate_vuln_scan,
	}])
	verified := {
		_verified_statement_provenance("clair-scan", its_att),
		{"statement": wrong_subject, "provenance": its_att},
		{"statement": non_test_statement, "provenance": its_att},
		_verified_statement_provenance("taskrun", taskrun_att),
	}

	assertions.assert_equal(
		{its_att},
		lib.its_pipelinerun_attestations,
	) with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as verified
		with intoto.verified_statement_provenances as verified
}

test_build_and_its_task_sources_remain_separate if {
	build_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("buildah")])
	its_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("clair-scan")])
	verified := {_verified_statement_provenance("clair-scan", its_att)}

	assertions.assert_equal(
		{"buildah"},
		_task_names(lib.tasks_from_pipelinerun),
	) with input.attestations as [build_att]
		with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as verified
		with intoto.verified_statement_provenances as verified

	assertions.assert_equal(
		{"clair-scan"},
		_task_names(lib.tasks_from_its_pipelineruns),
	) with input.attestations as [build_att]
		with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as verified
		with intoto.verified_statement_provenances as verified
}

test_task_names_from_tasks_includes_parameterized_names if {
	task := tekton_test.with_params(
		tekton_test.slsav1_task("clair-scan"),
		[{"name": "MODE", "value": "fast"}],
	)
	att := tekton_test.slsav1_attestation([task])

	assertions.assert_equal(
		{"clair-scan", "clair-scan[MODE=fast]"},
		lib.task_names_from_tasks(lib.tasks_from_attestations([att])),
	)
}

test_discovered_task_names_unions_and_deduplicates_sources if {
	build_att := tekton_test.slsav1_attestation([tekton_test.slsav1_task("clair-scan")])
	its_att := tekton_test.slsav1_attestation([
		tekton_test.slsav1_task("clair-scan"),
		tekton_test.slsav1_task("sast-snyk-check"),
	])
	associated := {_verified_statement_provenance("tests", its_att)}

	assertions.assert_equal(
		{"clair-scan", "sast-snyk-check"},
		lib.discovered_task_names,
	) with input.attestations as [build_att]
		with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as associated
}

test_discovered_task_names_empty_without_sources if {
	assertions.assert_empty(lib.discovered_task_names) with input.attestations as []
		with input.image.digest as "sha256:abc123"
		with intoto.associated_statement_provenances as set()
}

test_slsa_provenance_attestations if {
	assertions.assert_equal(lib.slsa_provenance_attestations, []) with input.attestations as []

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
	assertions.assert_equal(lib.slsa_provenance_attestations, expected) with input.attestations as attestations
}

test_pr_attestations_v1 if {
	# Test v1.0 PipelineRun attestation
	assertions.assert_equal([mock_pr_att], lib.pipelinerun_attestations) with input.attestations as [
		mock_tr_att,
		mock_pr_att,
		garbage_att,
	]
}

test_pr_attestations_v02 if {
	# Test v0.2 PipelineRun attestation
	assertions.assert_equal([mock_pr_att_legacy], lib.pipelinerun_attestations) with input.attestations as [
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
	assertions.assert_equal(
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
	assertions.assert_equal([], lib.pipelinerun_attestations) with input.attestations as [
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

	# Attestations with no runSpec (e.g. empty externalParameters) are included
	# because the runSpec guard only applies when runSpec exists.
	provenance_no_run_spec := json.patch(provenance_with_pr_spec, [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/externalParameters",
		"value": {},
	}])
	expected := [provenance_with_pr_spec, provenance_with_pr_ref, provenance_no_run_spec]
	assertions.assert_equal(expected, lib.pipelinerun_slsa_provenance_v1) with input.attestations as attestations
}

test_tr_attestations if {
	assertions.assert_equal([mock_tr_att], lib.taskrun_attestations) with input.attestations as [
		mock_tr_att,
		mock_pr_att,
		garbage_att,
	]

	assertions.assert_equal([], lib.taskrun_attestations) with input.attestations as [mock_pr_att, garbage_att]
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

	assertions.assert_equal(expected, att_mock_helper("result-name", {"foo": "bar"}, "mytask"))
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
					"bundle": "registry.img/name:tag@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700",
				},
				"results": [{
					"name": "result-name",
					"value": "{\"foo\":\"bar\"}",
				}],
			}]},
		},
	}}

	assertions.assert_equal(expected, att_mock_helper_ref(
		"result-name",
		{"foo": "bar"},
		"mytask",
		"registry.img/name:tag@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700",
	))
}

test_results_from_tests if {
	assertions.assert_equal("TEST_OUTPUT", lib.task_test_result_name)

	expected := {
		"value": {"result": "SUCCESS", "foo": "bar"},
		"name": "mytask",
		"bundle": "registry.img/acceptable@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700",
	}

	att1 := att_mock_helper_ref(
		lib.task_test_result_name, {
			"result": "SUCCESS",
			"foo": "bar",
		},
		"mytask", trusted_bundle_ref,
	)
	assertions.assert_equal([expected], lib.results_from_tests) with input.attestations as [att1]

	# An edge case that may never happen
	att2 := att_mock_helper_ref(
		lib.task_test_result_name, {
			"result": "SUCCESS",
			"foo": "bar",
		},
		"mytask", trusted_bundle_ref,
	)
	assertions.assert_equal([expected], lib.results_from_tests) with input.attestations as [att2]

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
	assertions.assert_equal([expected], lib.results_from_tests) with input.attestations as [att3]
}

test_unmarshall_json if {
	assertions.assert_equal({"a": 1, "b": "c"}, lib.unmarshal("{\"a\":1,\"b\":\"c\"}"))
	assertions.assert_equal("not JSON", lib.unmarshal("not JSON"))
	assertions.assert_equal("", lib.unmarshal(""))
}

test_param_values if {
	assertions.assert_equal(lib.param_values("spam"), {"spam"})
	assertions.assert_equal(lib.param_values(["spam", "eggs"]), {"spam", "eggs"})
	assertions.assert_equal(lib.param_values({"maps": "spam", "sgge": "eggs"}), {"spam", "eggs"})

	not lib.param_values(123)
}

test_result_values if {
	assertions.assert_equal(lib.result_values({"type": "string", "value": "spam"}), {"spam"})
	assertions.assert_equal(lib.result_values({"type": "array", "value": ["spam", "eggs"]}), {"spam", "eggs"})
	assertions.assert_equal(lib.result_values({"type": "object", "value": {"maps": "spam", "sgge": "eggs"}}), {"spam", "eggs"})

	not lib.result_values(123)
}

test_attestation_materials if {
	# SLSA v0.2: materials are just the mock materials
	att_v02 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	materials_v02 := lib.attestation_materials(att_v02)
	assertions.assert_equal(materials_v02, _mock_materials)

	# SLSA v1.0: resolvedDependencies includes both task dependencies and materials
	att_v1 := _attestation_v1_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	materials_v1 := lib.attestation_materials(att_v1)
	expected_v1 := array.concat(tekton_test.resolved_dependencies([_build_task]), _mock_materials)
	assertions.assert_equal(materials_v1, expected_v1)
}

# Mock materials for attestations (usable for both v0.2 and v1.0)
_mock_materials := [
	{
		"digest": {"sha256": "abc1230000000000000000000000000000000000000000000000000000abc123"},
		"uri": "oci://registry.img/spam",
	},
	{
		"digest": {"sha1": "def456"},
		"uri": "git+https://example.com/repo.git",
	},
]

# Helper to create a build task (has IMAGE_URL and IMAGE_DIGEST)
_build_task := {
	"name": "buildah",
	"ref": {"kind": "Task", "name": "buildah", "bundle": trusted_bundle_ref},
	"results": [
		{"name": "IMAGE_URL", "value": "quay.io/test/image:tag"},
		{"name": "IMAGE_DIGEST", "value": "sha256:abc1230000000000000000000000000000000000000000000000000000abc123"},
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
		"materials": _mock_materials,
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
			"resolvedDependencies": array.concat(tekton_test.resolved_dependencies(tasks), _mock_materials),
		},
		"runDetails": {"metadata": {
			"buildFinishedOn": build_finished_on,
			"buildStartedOn": "2025-01-01T00:00:00Z",
		}},
	},
}}

# Helper to create SLSA v1.0 attestation with spec-compliant finishedOn
_attestation_v1_with_finished_on(finished_on, tasks) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": lib.tekton_slsav1_pipeline_run,
			"externalParameters": {"runSpec": {"pipelineSpec": {}}},
			"resolvedDependencies": array.concat(tekton_test.resolved_dependencies(tasks), _mock_materials),
		},
		"runDetails": {"metadata": {
			"finishedOn": finished_on,
			"startedOn": "2025-01-01T00:00:00Z",
		}},
	},
}}

test_pipelinerun_attestations_single_v1_finished_on if {
	# Single v1.0 attestation using spec-compliant finishedOn - should be returned
	att := _attestation_v1_with_finished_on("2025-01-20T15:45:00Z", [_build_task])
	expected := [att]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as [att]
}

test_pipelinerun_attestations_multiple_v1_finished_on if {
	# Multiple v1.0 attestations using spec-compliant finishedOn - should return the latest
	att1 := _attestation_v1_with_finished_on("2025-01-15T10:30:00Z", [_build_task])
	att2 := _attestation_v1_with_finished_on("2025-01-20T15:45:00Z", [_build_task])
	att3 := _attestation_v1_with_finished_on("2025-01-18T12:00:00Z", [_build_task])
	attestations := [att1, att2, att3]
	expected := [att2]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_single_v02 if {
	# Test single v0.2 attestation
	att := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	expected := [att]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as [att]
}

test_pipelinerun_attestations_multiple_v02_latest_first if {
	# Multiple v0.2 attestations, latest is first in list
	att1 := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	att2 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	attestations := [att1, att2]
	expected := [att1]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_multiple_v02_latest_last if {
	# Multiple v0.2 attestations, latest is last in list
	att1 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	att2 := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	attestations := [att1, att2]
	expected := [att2]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_multiple_v02_middle if {
	# Multiple v0.2 attestations, latest is in the middle
	att1 := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	att2 := _attestation_v02_with_metadata("2025-01-25T20:00:00Z", [_build_task])
	att3 := _attestation_v02_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	attestations := [att1, att2, att3]
	expected := [att2]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
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
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_multiple_v1_missing_timestamp if {
	# Multiple v1.0 attestations where at least one doesn't have a timestamp - should return empty
	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_results := tekton_test.with_results(
		_task_base,
		[
			{"name": "IMAGE_URL", "type": "string", "value": "quay.io/test/image:tag"},
			# regal ignore:line-length
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc1230000000000000000000000000000000000000000000000000000abc123"},
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
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_mixed_formats if {
	# Test with both v0.2 and v1.0 attestations - should return both (one per type)
	v02_task := _build_task
	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_results := tekton_test.with_results(
		_task_base,
		[
			{"name": "IMAGE_URL", "type": "string", "value": "quay.io/test/image:tag"},
			# regal ignore:line-length
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc1230000000000000000000000000000000000000000000000000000abc123"},
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
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_empty if {
	# No attestations should return empty list
	expected := []
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as []
}

test_pipelinerun_attestations_single_no_timestamp if {
	# Single attestation without timestamp should still be returned
	att := _attestation_v02_with_metadata("2025-01-15T10:30:00Z", [_non_build_task])
	expected := [att]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as [att]
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
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_v1_multiple if {
	# Test multiple v1.0 attestations - should return the latest
	v1_att1 := _attestation_v1_with_metadata("2025-01-15T10:30:00Z", [_build_task])
	v1_att2 := _attestation_v1_with_metadata("2025-01-20T15:45:00Z", [_build_task])
	attestations := [v1_att1, v1_att2]
	expected := [v1_att2]
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as attestations
}

test_pipelinerun_attestations_v1_single_no_timestamp if {
	# Test single v1.0 attestation without timestamp - should still return it
	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_results := tekton_test.with_results(
		_task_base,
		[
			{"name": "IMAGE_URL", "type": "string", "value": "quay.io/test/image:tag"},
			# regal ignore:line-length
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc1230000000000000000000000000000000000000000000000000000abc123"},
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
	assertions.assert_equal(expected, lib.pipelinerun_attestations) with input.attestations as [v1_att]
}

test_custom_v02_build_type if {
	# A non-Tekton v0.2 buildType should be recognized when added via rule_data
	custom_type := "https://pnc.example.com/v1/PipelineRun"
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": custom_type,
			"metadata": {"buildFinishedOn": "2025-01-15T10:30:00Z"},
		},
	}}

	# Without rule_data, the custom buildType is not recognized
	assertions.assert_equal([], lib.pipelinerun_slsa_provenance02) with input.attestations as [att]

	# With rule_data including the custom buildType (along with defaults), it is recognized
	assertions.assert_equal([att], lib.pipelinerun_slsa_provenance02) with input.attestations as [att]
		with data.rule_data__configuration__ as {"allowed_provenance_build_types": [custom_type]}
}

test_custom_v1_build_type if {
	# A non-Tekton v1 buildType should be recognized when added via rule_data
	# and should NOT require the runSpec/pipelineRef/pipelineSpec guard
	custom_type := "https://pnc.example.com/v1/slsa"
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": custom_type,
			"externalParameters": {"some_param": "some_value"},
		}},
	}}

	# Without rule_data, the custom buildType is not recognized
	assertions.assert_equal([], lib.pipelinerun_slsa_provenance_v1) with input.attestations as [att]

	# With rule_data including the custom buildType, it is recognized and does not
	# need the runSpec guard
	assertions.assert_equal([att], lib.pipelinerun_slsa_provenance_v1) with input.attestations as [att]
		with data.rule_data__configuration__ as {"allowed_provenance_build_types": [custom_type]}
}

test_custom_v1_build_type_tekton_still_guarded if {
	# Tekton v1 buildTypes should still require the runSpec guard
	tekton_att_with_task_ref := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": {"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa",
			"externalParameters": {"runSpec": {"taskRef": {}}},
		}},
	}}

	# Tekton buildType with taskRef should still be filtered out
	assertions.assert_equal([], lib.pipelinerun_slsa_provenance_v1) with input.attestations as [tekton_att_with_task_ref]
}
