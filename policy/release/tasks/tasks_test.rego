# regal ignore:file-length
package tasks_test

import rego.v1

import data.lib
import data.lib.tekton
import data.lib.tekton_test
import data.tasks

test_no_tasks_present if {
	expected := {{
		"code": "tasks.pipeline_has_tasks",
		"msg": "No tasks found in PipelineRun attestation",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as [{"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": []},
	}}}]
		with ec.oci.image_manifests as _mock_image_manifests

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as [tekton_test.slsav1_attestation([])]
		with ec.oci.image_manifests as _mock_image_manifests
}

# regal ignore:rule-length
test_failed_tasks if {
	expected := {
		{
			"code": "tasks.successful_pipeline_tasks",
			"msg": "Pipeline task \"av-scanner\" did not complete successfully, \"Failed\"",
			"term": "av-scanner",
		},
		{
			"code": "tasks.successful_pipeline_tasks",
			"msg": "Pipeline task \"cve-scanner\" did not complete successfully, \"MISSING\"",
			"term": "cve-scanner",
		},
	}

	given_tasks := [
		_task("buildah"),
		json.patch(_task("av-scanner"), [{
			"op": "add",
			"path": "/status",
			"value": "Failed",
		}]),
		json.remove(_task("cve-scanner"), ["/status"]),
	]

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": given_tasks},
		},
	}}]
		with ec.oci.image_manifests as _mock_image_manifests

	slsav1_tasks := [
		tekton_test.with_bundle(tekton_test.slsav1_task("buildah"), _bundle),
		tekton_test.with_bundle(
			tekton_test.with_conditions(
				tekton_test.slsav1_task("av-scanner"),
				[{"type": "Succeeded", "status": "False"}],
			),
			_bundle,
		),
		tekton_test.with_bundle(
			tekton_test.with_conditions(
				tekton_test.slsav1_task("cve-scanner"),
				[],
			),
			_bundle,
		),
	]

	lib.assert_equal_results(
		tasks.deny,
		expected,
	) with input.attestations as [tekton_test.slsav1_attestation_full(
		slsav1_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_required_tasks_met if {
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_attestations := [tekton_test.slsav1_attestation(_slsav1_expected_required_tasks)]
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
}

test_required_tasks_met_no_label if {
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["pipeline-required-tasks"] as {}
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	attestations_no_label := _attestations_with_tasks_no_label(_slsav02_expected_required_tasks, [])
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations_no_label

	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		_slsav1_expected_required_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data["pipeline-required-tasks"] as {}
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests

	lib.assert_empty(tasks.deny) with data["required-tasks"] as _time_based_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as [tekton_test.slsav1_attestation(_slsav1_expected_required_tasks)]
}

test_required_tasks_warning_no_label if {
	attestations := _attestations_with_tasks_no_label(_slsav02_expected_required_tasks, [])
	expected := {{
		"code": "tasks.pipeline_required_tasks_list_provided",
		"msg": "Required tasks do not exist for pipeline",
	}}
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_attestations := [tekton_test.slsav1_attestation(_slsav1_expected_required_tasks)]
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
}

test_required_tasks_not_met if {
	missing_tasks := {"buildah"}
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks - missing_tasks, [])

	expected := _missing_tasks_violation(missing_tasks)
	lib.assert_equal_results(
		expected,
		tasks.deny,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_filtered_tasks := [task |
		some task in _slsav1_expected_required_tasks
		task_name := tekton.task_name(task)
		not missing_tasks[task_name]
	]
	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		slsav1_filtered_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_equal_results(
		expected,
		tasks.deny,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
}

test_future_required_tasks_met if {
	attestations := _attestations_with_tasks(_slsav02_expected_future_required_tasks, [])
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		_slsav1_expected_future_required_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
}

test_future_required_tasks_not_met if {
	missing_tasks := {"conftest-clair"}
	attestations := _attestations_with_tasks(_slsav02_expected_future_required_tasks - missing_tasks, [])

	expected := _missing_tasks_warning(missing_tasks)
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_filtered_tasks := [task |
		some task in _slsav1_expected_future_required_tasks
		task_name := tekton.task_name(task)
		not missing_tasks[task_name]
	]
	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		slsav1_filtered_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
}

test_extra_tasks_ignored if {
	attestations := _attestations_with_tasks(_slsav02_expected_future_required_tasks | {"spam"}, [])
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		array.concat(
			_slsav1_expected_future_required_tasks,
			[tekton_test.with_bundle(tekton_test.slsav1_task("spam"), _bundle)],
		),
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]

	# regal ignore:line-length
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
}

test_current_equal_latest if {
	required_tasks := {"generic": [{
		"effective_on": "2021-01-01T00:00:00Z",
		"tasks": _required_pipeline_tasks.generic[0].tasks,
	}]}
	attestations := _attestations_with_tasks(_slsav02_expected_future_required_tasks, [])

	lib.assert_empty(tasks.deny | tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations
}

test_current_equal_latest_also if {
	required_tasks := {"generic": [{
		"effective_on": "2021-01-01T00:00:00Z",
		"tasks": _required_pipeline_tasks.generic[0].tasks,
	}]}
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks, [])

	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	expected_denies := _missing_tasks_violation(_slsav02_expected_future_required_tasks - _slsav02_expected_required_tasks)
	lib.assert_equal_results(expected_denies, tasks.deny) with data["pipeline-required-tasks"] as required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		_slsav1_expected_required_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests

	lib.assert_equal_results(expected_denies, tasks.deny) with data["pipeline-required-tasks"] as required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
}

# regal ignore:rule-length
test_parameterized if {
	with_wrong_parameter := [
		{
			"status": "Succeeded",
			"ref": {
				"name": "label-check",
				"kind": "Task",
				"bundle": _bundle,
			},
			"invocation": {"parameters": {"POLICY_NAMESPACE": "something-else"}},
		},
		{
			"status": "Succeeded",
			"ref": {
				"name": "label-check",
				"kind": "Task",
				"bundle": _bundle,
			},
			"invocation": {"parameters": {"POLICY_NAMESPACE": "optional_checks"}},
		},
	]
	attestations := _attestations_with_tasks({"git-clone", "buildah"}, with_wrong_parameter)

	expected := _missing_tasks_violation({"label-check[POLICY_NAMESPACE=required_checks]"})
	lib.assert_equal_results(
		tasks.deny,
		expected,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	_slsav1_task1_base := tekton_test.slsav1_task("label-check")
	_slsav1_task1_w_bundle = tekton_test.with_bundle(_slsav1_task1_base, _bundle)
	slsav1_task1 = tekton_test.with_params(
		_slsav1_task1_w_bundle,
		[{"name": "POLICY_NAMESPACE", "value": "something-else"}],
	)

	_slsav1_task2_base := tekton_test.slsav1_task("label-check")
	_slsav1_task2_w_bundle = tekton_test.with_bundle(_slsav1_task2_base, _bundle)
	slsav1_task2 = tekton_test.with_params(
		_slsav1_task2_w_bundle,
		[{"name": "POLICY_NAMESPACE", "value": "optional_checks"}],
	)

	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		[
			tekton_test.with_bundle(tekton_test.slsav1_task("git-clone"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("buildah"), _bundle),
			slsav1_task1,
			slsav1_task2,
		],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_equal_results(
		tasks.deny,
		expected,
	) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
		with ec.oci.image_manifests as _mock_image_manifests
}

test_required_tasks_founds_data if {
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks, [])
	expected := {{
		"code": "tasks.required_tasks_list_provided",
		"msg": "Missing required required-tasks data",
	}}
	lib.assert_equal_results(expected, tasks.deny) with data["required-tasks"] as []
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations
		with data["pipeline-required-tasks"] as {}

	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		_slsav1_expected_required_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_equal_results(expected, tasks.deny) with data["required-tasks"] as []
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations with data["pipeline-required-tasks"] as {}
}

test_missing_required_pipeline_data if {
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks, [])
	expected := {{
		"code": "tasks.pipeline_required_tasks_list_provided",
		"msg": "Required tasks do not exist for pipeline",
	}}
	lib.assert_equal_results(expected, tasks.warn) with data["required-tasks"] as _slsav02_expected_required_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations

	slsav1_attestations := [tekton_test.slsav1_attestation_full(
		_slsav1_expected_required_tasks,
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]

	# we use _slsav02_expected_required_tasks as rule data because it fits the rule data format
	lib.assert_equal_results(expected, tasks.warn) with data["required-tasks"] as _slsav02_expected_required_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as slsav1_attestations
}

test_multiple_conditions_in_status if {
	conditions := [
		{
			"type": "Succeeded",
			"status": "True",
		},
		{
			"type": "Succeeded",
			"status": "False",
		},
		{"type": "invalid"},
	]
	slsav1_task := tekton_test.with_conditions(tekton_test.slsav1_task("buildah"), conditions)

	lib.assert_equal(["Succeeded", "Failed"], tasks._status(slsav1_task))
}

test_invalid_status_conditions if {
	conditions := []
	slsav1_task1 := tekton_test.with_conditions(tekton_test.slsav1_task("buildah"), conditions)
	lib.assert_equal(["MISSING"], tasks._status(slsav1_task1))

	given_task := json.remove(_task("buildah"), ["/status"])
	lib.assert_equal(["MISSING"], tasks._status(given_task))
}

test_one_of_required_tasks if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "c1", "d2", "e", "f"], [])
	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d2", "d3"], ["e"]},
		"effective_on": "2009-01-02T00:00:00Z",
	}]}
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestation_v02

	attestation_v1 := [tekton_test.slsav1_attestation_full(
		[
			tekton_test.with_bundle(tekton_test.slsav1_task("a"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("b"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("c1"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("d2"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("e"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("f"), _bundle),
		],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_empty(tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestation_v1
}

test_one_of_required_tasks_missing if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "d2", "e", "f"], [])

	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d3"]},
		"effective_on": "2009-01-02T00:00:00Z",
	}]}

	expected := {
		{
			"code": "tasks.required_tasks_found",
			"msg": `One of "c1", "c2", "c3" tasks is missing`,
			"term": ["c1", "c2", "c3"],
		},
		{
			"code": "tasks.required_tasks_found",
			"msg": `One of "d1", "d3" tasks is missing`,
			"term": ["d1", "d3"],
		},
	}

	lib.assert_equal_results(expected, tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestation_v02

	attestation_v1 := tekton_test.slsav1_attestation_full(
		[
			tekton_test.with_bundle(tekton_test.slsav1_task("a"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("b"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("d2"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("e"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("f"), _bundle),
		],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)
	lib.assert_equal_results(expected, tasks.deny) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as [attestation_v1]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_future_one_of_required_tasks if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "c1", "d2", "e", "f"], [])
	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d2", "d3"], ["e"]},
		"effective_on": "2099-01-02T00:00:00Z",
	}]}
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestation_v02

	attestation_v1 := [tekton_test.slsav1_attestation_full(
		[
			tekton_test.with_bundle(tekton_test.slsav1_task("a"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("b"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("c1"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("d2"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("e"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("f"), _bundle),
		],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_empty(tasks.warn) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestation_v1
}

test_future_one_of_required_tasks_missing if {
	attestation_v02 := _attestations_with_tasks(["a", "b", "d2", "e", "f"], [])

	data_required_tasks := {"generic": [{
		"tasks": {"a", ["c1", "c2", "c3"], ["d1", "d3"]},
		"effective_on": "2099-01-02T00:00:00Z",
	}]}

	expected := {
		{
			"code": "tasks.future_required_tasks_found",
			"msg": `One of "c1", "c2", "c3" tasks is missing and will be required on 2099-01-02T00:00:00Z`,
			"term": ["c1", "c2", "c3"],
		},
		{
			"code": "tasks.future_required_tasks_found",
			"msg": `One of "d1", "d3" tasks is missing and will be required on 2099-01-02T00:00:00Z`,
			"term": ["d1", "d3"],
		},
	}
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestation_v02

	attestation_v1 := [tekton_test.slsav1_attestation_full(
		[
			tekton_test.with_bundle(tekton_test.slsav1_task("a"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("b"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("d2"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("e"), _bundle),
			tekton_test.with_bundle(tekton_test.slsav1_task("f"), _bundle),
		],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]
	lib.assert_equal_results(
		expected,
		tasks.warn,
	) with data["pipeline-required-tasks"] as data_required_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestation_v1
}

test_future_required_tasks if {
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks - {"buildah"}, [{
		"name": "buildah",
		"ref": {"name": "buildah", "kind": "Task", "bundle": "registry.io/repository/unacceptable:0.1"},
	}])
	expected := {{
		"code": "tasks.future_required_tasks_found",
		"msg": "Task \"conftest-clair\" is missing and will be required on 2099-01-02T00:00:00Z",
		"term": "conftest-clair",
	}}

	lib.assert_equal_results(expected, tasks.warn) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations
}

test_required_task_from_untrusted if {
	attestations := _attestations_with_tasks(_slsav02_expected_required_tasks - {"buildah"}, [{
		"name": "buildah",
		"status": "Succeeded",
		"ref": {"name": "buildah", "kind": "Task", "bundle": _untrusted_bundle},
	}])
	expected := {{
		"code": "tasks.required_untrusted_task_found",
		"msg": "Required task \"buildah\" is required and present but not from a trusted task",
		"term": "buildah",
	}}
	lib.assert_equal_results(expected, tasks.deny) with data["pipeline-required-tasks"] as _required_pipeline_tasks
		with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations
}

test_pinned_task_refs_slsa_v0_2 if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [
				# Unpinned
				{
					"name": "pipeline-task-01",
					"status": "Succeeded",
					"ref": {
						"kind": "Task",
						"resolver": "git",
						"params": [{"name": "revision", "value": "main"}],
					},
					"invocation": {"environment": {"labels": {"tekton.dev/task": "task-01"}}},
				},
				# Pinned
				{
					"name": "pipeline-task-02",
					"status": "Succeeded",
					"ref": {
						"kind": "Task",
						"resolver": "git",
						"params": [{"name": "revision", "value": "48df630394794f28142224295851a45eea5c63ae"}],
					},
					"invocation": {"environment": {"labels": {"tekton.dev/task": "task-02"}}},
				},
			]},
		},
	}}

	expected := {{
		"code": "tasks.pinned_task_refs",
		"msg": "Task task-01 is used by pipeline task pipeline-task-01 via an unpinned reference.",
		"term": "task-01",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as [att]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_pinned_task_refs_slsa_v1 if {
	_task_base := tekton_test.resolved_slsav1_task("pipeline-task", [], [])

	task_pinned_ref := json.patch(_task_base, [
		{
			"op": "replace",
			"path": "/metadata/labels/tekton.dev~1task",
			"value": "task-01",
		},
		{
			"op": "replace",
			"path": "/spec/taskRef",
			"value": {
				"resolver": "git",
				"params": [
					{"name": "name", "value": "task-01"},
					{"name": "revision", "value": "main"},
					{"name": "kind", "value": "task"},
				],
			},
		},
	])
	task_unpinned_ref := json.patch(_task_base, [
		{
			"op": "replace",
			"path": "/metadata/labels/tekton.dev~1task",
			"value": "task-02",
		},
		{
			"op": "replace",
			"path": "/spec/taskRef",
			"value": {
				"resolver": "git",
				"params": [
					{"name": "name", "value": "task-02"},
					{"name": "revision", "value": "48df630394794f28142224295851a45eea5c63ae"},
					{"name": "kind", "value": "task"},
				],
			},
		},
	])

	att1 := tekton_test.slsav1_attestation_full(
		[task_pinned_ref, task_unpinned_ref],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)

	expected := {{
		"code": "tasks.pinned_task_refs",
		"msg": "Task task-01 is used by pipeline task pipeline-task via an unpinned reference.",
		"term": "task-01",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as [att1]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_deprecated_slsa_v0_2 if {
	attestation := _attestations_with_tasks({}, [object.union(
		_task("task"),
		{"invocation": {"environment": {"annotations": {tasks._expires_on_annotation: "2200-01-01T00:00:00Z"}}}},
	)])

	expected := {{
		"code": "tasks.unsupported",
		# regal ignore:line-length
		"msg": `Task "task" is used by pipeline task "task" is or will be unsupported as of 2200-01-01T00:00:00Z. Upgrade to a newer version of the Task.`,
		"term": "task",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as attestation
		with data["task-bundles"] as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
}

test_expired_slsa_v0_2 if {
	attestation := _attestations_with_tasks({}, [object.union(
		_task("task"),
		{"invocation": {"environment": {"annotations": {tasks._expires_on_annotation: "2000-01-01T00:00:00Z"}}}},
	)])

	expected := {{
		"code": "tasks.unsupported",
		# regal ignore:line-length
		"msg": `Task "task" is used by pipeline task "task" is or will be unsupported as of 2000-01-01T00:00:00Z. Upgrade to a newer version of the Task.`,
		"term": "task",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as attestation
		with data["task-bundles"] as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
}

test_deprecated_slsa_v1 if {
	task_with_annotation := tekton_test.with_annotations(
		tekton_test.with_bundle(tekton_test.slsav1_task("task"), _bundle),
		{tasks._expires_on_annotation: "2200-01-01T00:00:00Z"},
	)
	attestation := [tekton_test.slsav1_attestation_full(
		[task_with_annotation],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]

	expected := {{
		"code": "tasks.unsupported",
		# regal ignore:line-length
		"msg": `Task "task" is used by pipeline task "task" is or will be unsupported as of 2200-01-01T00:00:00Z. Upgrade to a newer version of the Task.`,
		"term": "task",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as attestation
		with data["task-bundles"] as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
}

test_expired_slsa_v1 if {
	task_with_annotation := tekton_test.with_annotations(
		tekton_test.with_bundle(tekton_test.slsav1_task("task"), _bundle),
		{tasks._expires_on_annotation: "2000-01-01T00:00:00Z"},
	)
	attestation := [tekton_test.slsav1_attestation_full(
		[task_with_annotation],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]

	expected := {{
		"code": "tasks.unsupported",
		# regal ignore:line-length
		"msg": `Task "task" is used by pipeline task "task" is or will be unsupported as of 2000-01-01T00:00:00Z. Upgrade to a newer version of the Task.`,
		"term": "task",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as attestation
		with data["task-bundles"] as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
}

test_expired_with_custom_message if {
	task_with_annotations := tekton_test.with_annotations(
		tekton_test.with_bundle(tekton_test.slsav1_task("task"), _bundle),
		{
			tasks._expires_on_annotation: "2000-01-01T00:00:00Z",
			tasks._expiry_msg_annotation: "The Task has been discontinued.",
		},
	)
	attestation := [tekton_test.slsav1_attestation_full(
		[task_with_annotations],
		{"pipelines.openshift.io/runtime": "generic"},
		{},
	)]

	expected := {{
		"code": "tasks.unsupported",
		# regal ignore:line-length
		"msg": `Task "task" is used by pipeline task "task" is or will be unsupported as of 2000-01-01T00:00:00Z. The Task has been discontinued.`,
		"term": "task",
	}}

	lib.assert_equal_results(tasks.deny, expected) with input.attestations as attestation
		with data["task-bundles"] as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
}

test_data_errors_on_required_tasks if {
	required_tasks := [
		{
			# No issues.
			"effective_on": "2099-01-02T00:00:00Z",
			"tasks": [
				["git-clone", "git-clone-oci-ta"],
				"buildah",
			],
		},
		{
			# Bad datetime
			"effective_on": "bad-datetime-format",
			"tasks": [
				["git-clone", "git-clone-oci-ta"],
				"buildah",
			],
		},
		{
			# Bad types all around
			"effective_on": {},
			"tasks": [[1, 2], 3],
		},
		{
			# Empty list of tasks.
			"effective_on": "2099-01-02T00:00:00Z",
			"tasks": [],
		},
		{
			# Empty task entry.
			"effective_on": "2099-01-02T00:00:00Z",
			"tasks": [
				[],
				"buildah",
			],
		},
	]

	expected := {
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 2.effective_on: Invalid type. Expected: string, given: object",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 2.tasks.0.0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 2.tasks.0.1: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 2.tasks.0: Must validate one and only one schema (oneOf)",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 2.tasks.1: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 2.tasks.1: Must validate one and only one schema (oneOf)",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 3.tasks: Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 4.tasks.0: Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": "Data required-tasks has unexpected format: 4.tasks.0: Must validate one and only one schema (oneOf)",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": `required-tasks[1].effective_on is not valid RFC3339 format: "bad-datetime-format"`,
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			"msg": `required-tasks[2].effective_on is not valid RFC3339 format: "{}"`,
			"severity": "failure",
		},
	}

	lib.assert_equal_results(tasks.deny, expected) with data["required-tasks"] as required_tasks
}

test_data_errors_on_pipeline_required_tasks if {
	# Since pipeline-required-tasks uses the schema for required-tasks, only perform basic tests
	pipeline_required_tasks := {
		# No issues
		"generic": [{
			"effective_on": "2099-01-02T00:00:00Z",
			"tasks": [
				["git-clone", "git-clone-oci-ta"],
				"buildah",
			],
		}],
		# Empty task list
		"docker": [{
			"effective_on": "2099-01-02T00:00:00Z",
			"tasks": [],
		}],
		# Bad datetime
		"spam": [{
			"effective_on": "bad-datetime-format",
			"tasks": [
				["git-clone", "git-clone-oci-ta"],
				"buildah",
			],
		}],
	}

	expected := {
		{
			"code": "tasks.data_provided",
			"msg": "Data pipeline-required-tasks has unexpected format: docker.0.tasks: Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "tasks.data_provided",
			# regal ignore:line-length
			"msg": `pipeline-required-tasks.spam[0].effective_on is not valid RFC3339 format: "bad-datetime-format"`,
			"severity": "failure",
		},
	}

	lib.assert_equal_results(tasks.deny, expected) with data["pipeline-required-tasks"] as pipeline_required_tasks
}

# Direct test of _missing_tasks function behavior
test_missing_tasks_function_behavior if {
	# Test with all required tasks present from trusted sources
	attestations_trusted := _attestations_with_tasks(_slsav02_expected_required_tasks, [])
	missing_trusted := tasks._missing_tasks(_slsav02_expected_required_tasks) with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations_trusted
	lib.assert_equal(set(), missing_trusted)

	# Test with some required tasks missing entirely
	missing_tasks := {"buildah", "git-clone"}
	attestations_missing := _attestations_with_tasks(_slsav02_expected_required_tasks - missing_tasks, [])
	missing_result := tasks._missing_tasks(_slsav02_expected_required_tasks) with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations_missing
	lib.assert_equal(missing_tasks, missing_result)

	# Test with required tasks present but from untrusted sources
	attestations_untrusted := _attestations_with_tasks(_slsav02_expected_required_tasks, [])

	# Even though all tasks are untrusted, _missing_tasks should return empty set
	# because all required tasks are PRESENT
	missing_untrusted := tasks._missing_tasks(_slsav02_expected_required_tasks) with data.trusted_tasks as {}
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as attestations_untrusted
	lib.assert_equal(set(), missing_untrusted)

	# Test mixed scenario: some tasks missing, some present but untrusted, some trusted
	mixed_attestations := _attestations_with_tasks({"git-clone"}, [{
		"name": "buildah",
		"status": "Succeeded",
		"ref": {"name": "buildah", "kind": "Task", "bundle": _untrusted_bundle},
	}])

	# Should only report the completely missing tasks, not the untrusted ones
	expected_missing_mixed := {
		"label-check[POLICY_NAMESPACE=required_checks]",
		"label-check[POLICY_NAMESPACE=optional_checks]",
	}
	missing_mixed := tasks._missing_tasks(_slsav02_expected_required_tasks) with data.trusted_tasks as _trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with input.attestations as mixed_attestations
	lib.assert_equal(expected_missing_mixed, missing_mixed)
}

_attestations_with_tasks(names, add_tasks) := attestations if {
	tasks := array.concat([t | some name in names; t := _task(name)], add_tasks)

	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": tasks},
			"invocation": {"environment": {"labels": {"pipelines.openshift.io/runtime": "generic"}}},
		},
	}}]
}

_attestations_with_tasks_no_label(names, add_tasks) := attestations if {
	tasks := array.concat([t | some name in names; t := _task(name)], add_tasks)

	attestations := [{"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": tasks},
		},
	}}]
}

_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)

	# regal ignore:redundant-existence-check
	parts[1]
	task_name := parts[0]
	pipeline_task_name := sprintf("%s", [task_name])

	task := {
		"name": pipeline_task_name,
		"status": "Succeeded",
		"ref": {"name": task_name, "kind": "Task", "bundle": _bundle},
		"invocation": {"parameters": {parts[1]: parts[2]}},
	}
}

_task(name) := task if {
	parts := regex.split(`[\[\]=]`, name)
	not parts[1]
	pipeline_task_name := sprintf("%s", [name])
	task := {
		"name": pipeline_task_name,
		"status": "Succeeded",
		"ref": {"name": name, "kind": "Task", "bundle": _bundle},
	}
}

_missing_tasks_violation(tasks) := {error |
	some task in tasks
	error := {
		"code": "tasks.required_tasks_found",
		"msg": sprintf("Required task %q is missing", [task]),
		"term": task,
	}
}

_missing_tasks_warning(tasks) := {warning |
	some task in tasks
	warning := {
		"code": "tasks.future_required_tasks_found",
		"msg": sprintf("Task %q is missing and will be required on 2099-01-02T00:00:00Z", [task]),
		"term": task,
	}
}

_slsav02_expected_required_tasks := {
	"git-clone",
	"buildah",
	"label-check[POLICY_NAMESPACE=required_checks]",
	"label-check[POLICY_NAMESPACE=optional_checks]",
}

_slsav1_expected_required_tasks := [
	tekton_test.with_bundle(tekton_test.slsav1_task("git-clone"), _bundle),
	tekton_test.with_bundle(tekton_test.slsav1_task("buildah"), _bundle),
	tekton_test.with_bundle(
		tekton_test.with_params(
			tekton_test.slsav1_task("label-check"),
			[{
				"name": "POLICY_NAMESPACE",
				"value": "required_checks",
			}],
		),
		_bundle,
	),
	tekton_test.with_bundle(
		tekton_test.with_params(
			tekton_test.slsav1_task("label-check"),
			[{
				"name": "POLICY_NAMESPACE",
				"value": "optional_checks",
			}],
		),
		_bundle,
	),
]

_slsav02_expected_future_required_tasks := {
	"git-clone",
	"buildah",
	"conftest-clair",
	"label-check[POLICY_NAMESPACE=required_checks]",
	"label-check[POLICY_NAMESPACE=optional_checks]",
}

_slsav1_expected_future_required_tasks := [
	tekton_test.with_bundle(
		tekton_test.slsav1_task("git-clone"),
		_bundle,
	),
	tekton_test.with_results(
		tekton_test.with_bundle(
			tekton_test.slsav1_task("buildah"),
			_bundle,
		),
		[],
	),
	tekton_test.with_bundle(
		tekton_test.slsav1_task("conftest-clair"),
		_bundle,
	),
	tekton_test.with_bundle(
		tekton_test.with_params(
			tekton_test.slsav1_task("label-check"),
			[{
				"name": "POLICY_NAMESPACE",
				"value": "required_checks",
			}],
		),
		_bundle,
	),
	tekton_test.with_bundle(
		tekton_test.with_params(
			tekton_test.slsav1_task("label-check"),
			[{
				"name": "POLICY_NAMESPACE",
				"value": "optional_checks",
			}],
		),
		_bundle,
	),
]

_required_pipeline_tasks := {"generic": [
	{
		"effective_on": "2099-01-02T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"conftest-clair",
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2099-01-01T00:00:00Z",
		"tasks": ["also-ignored"],
	},
	{
		"effective_on": "2022-12-01T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"not-required-in-future",
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2022-01-01T00:00:00Z",
		"tasks": ["ignored"],
	},
]}

_time_based_required_tasks := [
	{
		"effective_on": "2099-01-02T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"conftest-clair",
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2099-01-01T00:00:00Z",
		"tasks": ["also-ignored"],
	},
	{
		"effective_on": "2022-12-01T00:00:00Z",
		"tasks": [
			"git-clone",
			"buildah",
			"not-required-in-future",
			"label-check[POLICY_NAMESPACE=required_checks]",
			"label-check[POLICY_NAMESPACE=optional_checks]",
		],
	},
	{
		"effective_on": "2022-01-01T00:00:00Z",
		"tasks": ["ignored"],
	},
]

_bundle := "registry.img/spam:0.1@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

# regal ignore:line-length
_untrusted_bundle := "registry.io/repository/unacceptable:0.1@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_trusted_tasks := {"oci://registry.img/spam:0.1": [{
	"ref": "sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb",
	"effective_on": "2000-01-01T00:00:00Z",
}]}

# Mock function for ec.oci.image_manifests
# Returns a map of bundle_ref -> manifest for test bundles
_mock_image_manifests(refs) := {ref: manifest |
	some ref in refs
	manifest := {}
}
