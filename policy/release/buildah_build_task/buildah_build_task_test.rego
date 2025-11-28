package buildah_build_task_test

import rego.v1

import data.buildah_build_task
import data.lib
import data.lib.tekton_test

test_good_dockerfile_param if {
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "./Dockerfile"}}, _results)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts("buildah", [{"name": "DOCKERFILE", "value": "./Dockerfile"}], _slsav1_byproducts) # regal ignore:line-length
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_buildah_tasks if {
	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts([_slsav1_local_task], [], _slsav1_byproducts) # regal ignore:line-length

	expected := {{
		"name": "buildah",
		"params": [
			{"name": "IMAGE", "value": "quay.io/jstuart/hacbs-docker-build"},
			{"name": "DOCKERFILE", "value": "./image_with_labels/Dockerfile"},
		],
		"results": _results,
		"taskRef": {
			"params": [{"name": "name", "value": "buildah"}, {"name": "bundle", "value": "buildah-bundle"}, {"name": "kind", "value": "task"}], # regal ignore:line-length
			"resolver": "bundles",
		},
		"workspaces": [{"name": "buildah", "workspace": "buildah-workspace"}],
	}}
	lib.assert_equal(expected, buildah_build_task._buildah_tasks) with input.attestations as [slsav1_attestation]
}

test_dockerfile_param_https_source if {
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (https://Dockerfile) is an external source",
	}}

	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "https://Dockerfile"}}, _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	ext_source_task := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "https://Dockerfile",
			},
		],
	)
	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts([ext_source_task], [], _slsav1_byproducts) # regal ignore:line-length
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_dockerfile_param_http_source if {
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "http://Dockerfile"}}, _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	ext_source_task := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "http://Dockerfile",
			},
		],
	)
	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts([ext_source_task], [], _slsav1_byproducts) # regal ignore:line-length
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_missing_pipeline_run_attestations if {
	attestation := {"statement": {"predicate": {"buildType": "something/else"}}}
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	slsav1_attestation := tekton_test.slsav1_attestation([])
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_multiple_buildah_tasks if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			{
				"name": "b1",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "one/Dockerfile"}},
			},
			{
				"name": "b2",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "two/Dockerfile"}},
			},
		]},
	}}}
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	tasks := [
		_slsav1_local_task,
		_slsav1_local_task_with_refname("task1"),
		_slsav1_local_task_with_refname("task2"),
		_slsav1_local_task_with_refname("task3"),
	]

	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts(tasks, [], _slsav1_byproducts)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_multiple_buildah_tasks_one_with_external_dockerfile if {
	attestation := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [
			{
				"name": "b1",
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"invocation": {"parameters": {"DOCKERFILE": "one/Dockerfile"}},
				"results": _results,
			},
			{
				"name": "b2",
				"invocation": {"parameters": {"DOCKERFILE": "http://Dockerfile"}},
				"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
				"results": _results,
			},
		]},
	}}}
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	tasks := [
		_slsav1_local_task,
		_slsav1_local_task_with_refname("task1"),
		_slsav1_local_task_with_refname("task2"),
		_slsav1_local_task_with_refname("task3"),
		tekton_test.slsav1_task_with_params(
			"buildah",
			"buildah",
			[
				{
					"name": "IMAGE",
					"value": "quay.io/jstuart/hacbs-docker-build",
				},
				{
					"name": "DOCKERFILE",
					"value": "http://Dockerfile",
				},
			],
		),
	]

	slsav1_attestation := tekton_test.slsav1_attestation_with_params_and_byproducts(tasks, [], _slsav1_byproducts)

	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_add_capabilities_param if {
	expected := {{
		"code": "buildah_build_task.add_capabilities_param",
		"msg": "ADD_CAPABILITIES parameter is not allowed",
	}}

	task1 := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "./image_with_labels/Dockerfile",
			},
			{
				"name": "ADD_CAPABILITIES",
				"value": "spam",
			},
		],
	)
	attestation := tekton_test.slsav1_attestation_with_params_and_byproducts([task1], [], _slsav1_byproducts) # regal ignore:line-length
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	task2 := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "./image_with_labels/Dockerfile",
			},
			{
				"name": "ADD_CAPABILITIES",
				"value": "   ",
			},
		],
	)
	attestation_spaces := tekton_test.slsav1_attestation_with_params_and_byproducts([task2], [], _slsav1_byproducts) # regal ignore:line-length
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_spaces]
}

test_platform_param if {
	expected := {{
		"code": "buildah_build_task.platform_param",
		"msg": "PLATFORM parameter value \"linux-root/arm64\" is disallowed by regex \".*root.*\"",
	}}

	task1 := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "./image_with_labels/Dockerfile",
			},
			{
				"name": "PLATFORM",
				"value": "linux-root/arm64",
			},
		],
	)
	task2 := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "./image_with_labels/Dockerfile",
			},
			{
				"name": "PLATFORM",
				"value": "linux/arm64",
			},
		],
	)

	attestations := [
		tekton_test.slsav1_attestation_with_params_and_byproducts([task1], [], _slsav1_byproducts), # regal ignore:line-length
		tekton_test.slsav1_attestation_with_params_and_byproducts([task2], [], _slsav1_byproducts), # regal ignore:line-length
	]

	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as attestations
		with data.rule_data.disallowed_platform_patterns as [".*root.*"]
}

test_plat_patterns_rule_data_validation if {
	d := {"disallowed_platform_patterns": [
		# Wrong type and invalid regex
		1,
		# Duplicated items
		".*foo",
		".*foo",
		# Invalid regex in rego
		"(?=a)?b",
	]}

	expected := {
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			# regal ignore:line-length
			"msg": "Rule data disallowed_platform_patterns has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			"msg": "'\\x01' is not a valid regular expression in rego",
			"severity": "failure",
		},
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			"msg": "Rule data disallowed_platform_patterns has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "buildah_build_task.disallowed_platform_patterns_pattern",
			"msg": "\"(?=a)?b\" is not a valid regular expression in rego",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(buildah_build_task.deny, expected) with data.rule_data as d
}

test_privileged_nested_param if {
	expected := {{
		"code": "buildah_build_task.privileged_nested_param",
		"msg": "setting PRIVILEGED_NESTED parameter to true is not allowed",
	}}

	task := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "./image_with_labels/Dockerfile",
			},
			{
				"name": "PRIVILEGED_NESTED",
				"value": "true",
			},
		],
	)
	attestation := tekton_test.slsav1_attestation_with_params_and_byproducts([task], [], _slsav1_byproducts)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	task_empty := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "./image_with_labels/Dockerfile",
			},
			{
				"name": "PRIVILEGED_NESTED",
				"value": "",
			},
		],
	)
	attestation_empty := tekton_test.slsav1_attestation_with_params_and_byproducts([task_empty], [], _slsav1_byproducts)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_empty]

	task_false := tekton_test.slsav1_task_with_params(
		"buildah",
		"buildah",
		[
			{
				"name": "IMAGE",
				"value": "quay.io/jstuart/hacbs-docker-build",
			},
			{
				"name": "DOCKERFILE",
				"value": "./image_with_labels/Dockerfile",
			},
			{
				"name": "PRIVILEGED_NESTED",
				"value": "false",
			},
		],
	)
	attestation_false := tekton_test.slsav1_attestation_with_params_and_byproducts([task_false], [], _slsav1_byproducts)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_false]
}

_attestation(task_name, params, results) := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [{
		"name": task_name,
		"ref": {"kind": "Task", "name": task_name, "bundle": _bundle},
		"invocation": params,
		"results": results,
	}]},
}}}

_slsav1_local_task_with_refname(ref_name) := tekton_test.slsav1_task_with_params(
	"buildah",
	ref_name,
	[
		{
			"name": "IMAGE",
			"value": "quay.io/jstuart/hacbs-docker-build",
		},
		{
			"name": "DOCKERFILE",
			"value": "./image_with_labels/Dockerfile",
		},
	],
)

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_results := [
	{
		"name": "IMAGE_DIGEST",
		"value": "sha256:hash",
	},
	{
		"name": "IMAGE_URL",
		"value": "quay.io/jstuart/hacbs-docker-build:tag@sha256:hash",
	},
]

_slsav1_local_task := _slsav1_local_task_with_refname("buildah")

_slsav1_byproducts := [
	{
		"name": "taskRunResults/buildah/IMAGE_DIGEST",
		"content": base64.encode("sha256:hash"),
	},
	{
		"name": "taskRunResults/buildah/IMAGE_URL",
		"content": base64.encode("quay.io/jstuart/hacbs-docker-build:tag@sha256:hash"),
	},
]
