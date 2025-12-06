package buildah_build_task_test

import rego.v1

import data.buildah_build_task
import data.lib
import data.lib.tekton_test

test_good_dockerfile_param if {
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "./Dockerfile"}}, _results)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	task_base := tekton_test.slsav1_task("buildah")
	task_w_params := tekton_test.with_params(task_base, [{"name": "DOCKERFILE", "value": "./Dockerfile"}])
	task_w_results := tekton_test.with_results(task_w_params, _results)

	slsav1_attestation := tekton_test.slsav1_attestation([task_w_results])
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_buildah_tasks if {
	slsav1_attestation := tekton_test.slsav1_attestation([_buildah_task("buildah")])

	expected := {tekton_test.resolved_slsav1_task(
		"buildah",
		[
			{"name": "IMAGE", "value": "quay.io/jstuart/hacbs-docker-build"},
			{"name": "DOCKERFILE", "value": "./image_with_labels/Dockerfile"},
		],
		_results,
	)}
	lib.assert_equal(expected, buildah_build_task._buildah_tasks) with input.attestations as [slsav1_attestation]
}

test_dockerfile_param_https_source if {
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (https://Dockerfile) is an external source",
	}}

	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "https://Dockerfile"}}, _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	ext_source_task_base := tekton_test.slsav1_task("buildah")
	ext_source_task_w_params = tekton_test.with_params(
		ext_source_task_base,
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
	ext_source_task_full = tekton_test.with_results(ext_source_task_w_params, _results)

	slsav1_attestation := tekton_test.slsav1_attestation([ext_source_task_full])
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_dockerfile_param_http_source if {
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	attestation := _attestation("buildah", {"parameters": {"DOCKERFILE": "http://Dockerfile"}}, _results)
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	ext_source_task_base := tekton_test.slsav1_task("buildah")
	ext_source_task_w_params = tekton_test.with_params(
		ext_source_task_base,
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
	ext_source_task_full = tekton_test.with_results(ext_source_task_w_params, _results)

	slsav1_attestation := tekton_test.slsav1_attestation([ext_source_task_full])
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_missing_pipeline_run_attestations if {
	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {"buildType": "something/else"},
	}}
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	slsav1_attestation := tekton_test.slsav1_attestation([])
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_multiple_buildah_tasks if {
	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
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
		},
	}}
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation]

	tasks := [
		_buildah_task("buildah"),
		_buildah_task("task1"),
		_buildah_task("task2"),
		_buildah_task("task3"),
	]

	slsav1_attestation := tekton_test.slsav1_attestation(tasks)
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

# regal ignore:rule-length
test_multiple_buildah_tasks_one_with_external_dockerfile if {
	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
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
		},
	}}
	expected := {{
		"code": "buildah_build_task.buildah_uses_local_dockerfile",
		"msg": "DOCKERFILE param value (http://Dockerfile) is an external source",
	}}
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	ext_source_task_base := tekton_test.slsav1_task("buildah")
	ext_source_task_w_params = tekton_test.with_params(
		ext_source_task_base,
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
	ext_source_task_full = tekton_test.with_results(ext_source_task_w_params, _results)

	tasks := [
		_buildah_task("buildah"),
		_buildah_task("task1"),
		_buildah_task("task2"),
		_buildah_task("task3"),
		ext_source_task_full,
	]

	slsav1_attestation := tekton_test.slsav1_attestation(tasks)

	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [slsav1_attestation]
}

test_add_capabilities_param if {
	expected := {{
		"code": "buildah_build_task.add_capabilities_param",
		"msg": "ADD_CAPABILITIES parameter is not allowed",
	}}

	_task1_base := tekton_test.slsav1_task("buildah")
	_task1_w_params = tekton_test.with_params(
		_task1_base,
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
	task1 = tekton_test.with_results(_task1_w_params, _results)

	attestation := tekton_test.slsav1_attestation([task1])
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	_task2_base := tekton_test.slsav1_task("buildah")
	_task2_w_params = tekton_test.with_params(
		_task2_base,
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
	task2 = tekton_test.with_results(_task2_w_params, _results)

	attestation_spaces := tekton_test.slsav1_attestation([task2])
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_spaces]
}

test_platform_param_disallowed if {
	# Test v1.0 attestation with disallowed platform pattern
	expected := {{
		"code": "buildah_build_task.platform_param",
		"msg": "PLATFORM parameter value \"linux-root/arm64\" is disallowed by regex \".*root.*\"",
	}}

	_task1_base := tekton_test.slsav1_task("buildah")
	_task1_w_params = tekton_test.with_params(
		_task1_base,
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
	task1 = tekton_test.with_results(_task1_w_params, _results)

	_task2_base := tekton_test.slsav1_task("buildah")
	_task2_w_params = tekton_test.with_params(
		_task2_base,
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
	task2 = tekton_test.with_results(_task2_w_params, _results)

	# regal ignore:line-length
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [tekton_test.slsav1_attestation([task1])]
		with data.rule_data.disallowed_platform_patterns as [".*root.*"]

	lib.assert_empty(buildah_build_task.deny) with input.attestations as [tekton_test.slsav1_attestation([task2])]
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

	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_params = tekton_test.with_params(
		_task_base,
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
	task = tekton_test.with_results(_task_w_params, _results)

	attestation := tekton_test.slsav1_attestation([task])
	lib.assert_equal_results(expected, buildah_build_task.deny) with input.attestations as [attestation]

	_task_empty_base := tekton_test.slsav1_task("buildah")
	_task_empty_w_params = tekton_test.with_params(
		_task_empty_base,
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
	task_empty = tekton_test.with_results(_task_empty_w_params, _results)

	attestation_empty := tekton_test.slsav1_attestation([task_empty])
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_empty]

	_task_false_base := tekton_test.slsav1_task("buildah")
	_task_false_w_params = tekton_test.with_params(
		_task_false_base,
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
	task_false = tekton_test.with_results(_task_false_w_params, _results)

	attestation_false := tekton_test.slsav1_attestation([task_false])
	lib.assert_empty(buildah_build_task.deny) with input.attestations as [attestation_false]
}

_attestation(task_name, params, results) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": task_name,
			"ref": {"kind": "Task", "name": task_name, "bundle": _bundle},
			"invocation": params,
			"results": results,
		}]},
	},
}}

_buildah_task(ref_name) := task if {
	_task_base := tekton_test.slsav1_task("buildah")
	_task_w_name = tekton_test.with_ref_name(_task_base, ref_name)
	_task_w_params = tekton_test.with_params(
		_task_w_name,
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
	task = tekton_test.with_results(_task_w_params, _results)
}

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
