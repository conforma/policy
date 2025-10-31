package hermetic_task_test

import rego.v1

import data.hermetic_task
import data.lib
import data.lib.tekton_test

test_hermetic_task if {
	lib.assert_empty(hermetic_task.deny) with input.attestations as [_good_attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	slsav1_task := tekton_test.slsav1_task_with_params("buildah", "buildah", [{
		"name": "HERMETIC",
		"value": "$(params.hermetic)",
	}])
	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts(
		[slsav1_task], [{
			"name": "hermetic",
			"value": "true",
		}],
		[],
	)
	lib.assert_empty(hermetic_task.deny) with input.attestations as [slsav1_attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]
}

test_not_hermetic_task if {
	expected := {{
		"code": "hermetic_task.hermetic",
		"msg": "Task 'buildah' was not invoked with the hermetic parameter set",
	}}

	hermetic_not_true := json.patch(_good_attestation, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
		"value": "false",
	}])
	lib.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [hermetic_not_true]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	# regal ignore:line-length
	hermetic_missing := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC"])
	lib.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [hermetic_missing]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	slsav1_task := tekton_test.slsav1_task_with_params("buildah", "buildah", [{
		"name": "HERMETIC",
		"value": "$(params.hermetic)",
	}])
	slsav1_attestation_hermetic_false := tekton_test.slsav1_attestation_with_params_and_byproducts(
		[slsav1_task], [{
			"name": "hermetic",
			"value": "false",
		}],
		[],
	)
	lib.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [slsav1_attestation_hermetic_false]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	slsav1_task_not_hermetic := tekton_test.slsav1_task("buildah")
	slsav1_attestation_not_hermetic := tekton_test.slsav1_attestation([slsav1_task_not_hermetic])
	lib.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [slsav1_attestation_not_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]
}

test_many_hermetic_tasks if {
	task1 := {
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "buildah", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}

	task2 := {
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}

	attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2]},
	}}}
	lib.assert_empty(hermetic_task.deny) with input.attestations as [attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	slsav1_task1 := tekton_test.slsav1_task_with_params("buildah", "buildah", [{
		"name": "HERMETIC",
		"value": "$(params.hermetic)",
	}])
	slsav1_task2 := tekton_test.slsav1_task_with_params("run-script-oci-ta", "run-script-oci-ta", [{
		"name": "HERMETIC",
		"value": "$(params.hermetic)",
	}])
	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts(
		[slsav1_task1, slsav1_task2], [{
			"name": "hermetic",
			"value": "true",
		}],
		[],
	)

	attestation_mixed_hermetic_1 := json.patch(
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [task1, task2]},
		}}},
		[{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
			"value": "false",
		}],
	)
	expected_mixed_hermetic_1 := {{
		"code": "hermetic_task.hermetic",
		"msg": "Task 'buildah' was not invoked with the hermetic parameter set",
	}}

	# regal ignore:line-length
	lib.assert_equal_results(expected_mixed_hermetic_1, hermetic_task.deny) with input.attestations as [attestation_mixed_hermetic_1]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	attestation_mixed_hermetic_2 := json.patch(
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [task1, task2]},
		}}},
		[{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/1/invocation/parameters/HERMETIC",
			"value": "false",
		}],
	)
	expected_mixed_hermetic_2 := {{
		"code": "hermetic_task.hermetic",
		"msg": "Task 'run-script-oci-ta' was not invoked with the hermetic parameter set",
	}}

	# regal ignore:line-length
	lib.assert_equal_results(expected_mixed_hermetic_2, hermetic_task.deny) with input.attestations as [attestation_mixed_hermetic_2]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	slsav1_task1_mixed := tekton_test.slsav1_task_with_params("buildah", "buildah", [{
		"name": "HERMETIC",
		"value": "$(params.hermetic_1)",
	}])
	slsav1_task2_mixed := tekton_test.slsav1_task_with_params("run-script-oci-ta", "run-script-oci-ta", [{
		"name": "HERMETIC",
		"value": "$(params.hermetic_2)",
	}])
	slsav1_attestation_mixed_hermetic := tekton_test.slsav1_attestation_with_params_and_byproducts(
		[slsav1_task1_mixed, slsav1_task2_mixed], [
			{
				"name": "hermetic_1",
				"value": "true",
			},
			{
				"name": "hermetic_2",
				"value": "false",
			},
		],
		[],
	)

	# regal ignore:line-length
	lib.assert_equal_results(expected_mixed_hermetic_2, hermetic_task.deny) with input.attestations as [slsav1_attestation_mixed_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	attestation_non_hermetic := json.patch(
		{"statement": {"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [task1, task2]},
		}}},
		[
			{
				"op": "replace",
				"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC",
				"value": "false",
			},
			{
				"op": "replace",
				"path": "/statement/predicate/buildConfig/tasks/1/invocation/parameters/HERMETIC",
				"value": "false",
			},
		],
	)
	expected_non_hermetic := {
		{
			"code": "hermetic_task.hermetic",
			"msg": "Task 'buildah' was not invoked with the hermetic parameter set",
		},
		{
			"code": "hermetic_task.hermetic",
			"msg": "Task 'run-script-oci-ta' was not invoked with the hermetic parameter set",
		},
	}

	# regal ignore:line-length
	lib.assert_equal_results(expected_non_hermetic, hermetic_task.deny) with input.attestations as [attestation_non_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	slsav1_task1_non_hermetic := tekton_test.slsav1_task_with_params("buildah", "buildah", [{
		"name": "HERMETIC",
		"value": "$(params.hermetic)",
	}])
	slsav1_task2_non_hermetic := tekton_test.slsav1_task("run-script-oci-ta")
	slsav1_attestation_non_hermetic := tekton_test.slsav1_attestation_with_params_and_byproducts(
		[slsav1_task1_mixed, slsav1_task2_mixed], [{
			"name": "hermetic",
			"value": "false",
		}],
		[],
	)

	# regal ignore:line-length
	lib.assert_equal_results(expected_non_hermetic, hermetic_task.deny) with input.attestations as [slsav1_attestation_non_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]
}

test_task_is_hermetic if {
	task_hermetic := tekton_test.resolved_slsav1_task("some-task", [{"name": "HERMETIC", "value": "true"}], [])
	hermetic_task._task_is_hermetic(task_hermetic)

	task_not_hermetic := tekton_test.resolved_slsav1_task("some-task", [{"name": "HERMETIC", "value": "false"}], [])
	not hermetic_task._task_is_hermetic(task_not_hermetic)

	task_invalid_hermetic_param := tekton_test.resolved_slsav1_task(
		"some-task",
		[{"name": "HERMETIC", "value": "not a valid value"}],
		[],
	)
	not hermetic_task._task_is_hermetic(task_invalid_hermetic_param)

	task_hermetic_param_not_present := tekton_test.resolved_slsav1_task("some-task", [], [])
	not hermetic_task._task_is_hermetic(task_hermetic_param_not_present)
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"kind": "Task", "name": "buildah", "bundle": "reg.img/spam@sha256:abc"},
		"invocation": {"parameters": {"HERMETIC": "true"}},
	}]},
}}}
