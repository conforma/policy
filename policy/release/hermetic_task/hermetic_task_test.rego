package hermetic_task_test

import rego.v1

import data.hermetic_task

import data.lib
import data.lib.assertions
import data.lib.tekton_test

test_hermetic_task if {
	assertions.assert_empty(hermetic_task.deny) with input.attestations as [_good_attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	_task_base := tekton_test.slsav1_task("buildah")
	slsav1_task = tekton_test.with_params(
		_task_base,
		[
			{"name": "HERMETIC", "value": "true"},
			{"name": "enable-hermeto-proxy", "value": "true"},
		],
	)

	slsav1_attestation := tekton_test.slsav1_attestation([slsav1_task])
	assertions.assert_empty(hermetic_task.deny) with input.attestations as [slsav1_attestation]
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
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [hermetic_not_true]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	# regal ignore:line-length
	hermetic_missing := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/invocation/parameters/HERMETIC"])
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [hermetic_missing]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	_task_base := tekton_test.slsav1_task("buildah")
	slsav1_task = tekton_test.with_params(
		_task_base,
		[{
			"name": "HERMETIC",
			"value": "false",
		}],
	)

	slsav1_attestation_hermetic_false := tekton_test.slsav1_attestation([slsav1_task])
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [slsav1_attestation_hermetic_false]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	slsav1_task_not_hermetic := tekton_test.slsav1_task("buildah")
	slsav1_attestation_not_hermetic := tekton_test.slsav1_attestation([slsav1_task_not_hermetic])
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [slsav1_attestation_not_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]
}

test_many_hermetic_tasks if {
	task1 := {
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		# regal ignore:line-length
		"ref": {"kind": "Task", "name": "buildah", "bundle": "reg.img/spam@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		"invocation": {"parameters": {"HERMETIC": "true", "enable-hermeto-proxy": "true"}},
	}

	task2 := {
		"results": [
			{"name": "IMAGE_URL", "value": "registry/repo"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		# regal ignore:line-length
		"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		"invocation": {"parameters": {"HERMETIC": "true", "enable-hermeto-proxy": "true"}},
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [task1, task2]},
		},
	}}
	assertions.assert_empty(hermetic_task.deny) with input.attestations as [attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	_task_base_1 := tekton_test.slsav1_task("buildah")
	slsav1_task1 = tekton_test.with_params(
		_task_base_1,
		[
			{"name": "HERMETIC", "value": "true"},
			{"name": "enable-hermeto-proxy", "value": "true"},
		],
	)

	_task_base_2 := tekton_test.slsav1_task("run-script-oci-ta")
	slsav1_task2 = tekton_test.with_params(
		_task_base_2,
		[
			{"name": "HERMETIC", "value": "true"},
			{"name": "enable-hermeto-proxy", "value": "true"},
		],
	)

	slsav1_attestation := tekton_test.slsav1_attestation([slsav1_task1, slsav1_task2])
	assertions.assert_empty(hermetic_task.deny) with input.attestations as [slsav1_attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	attestation_mixed_hermetic_1 := json.patch(
		{"statement": {
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": {
				"buildType": lib.tekton_pipeline_run,
				"buildConfig": {"tasks": [task1, task2]},
			},
		}},
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
	assertions.assert_equal_results(expected_mixed_hermetic_1, hermetic_task.deny) with input.attestations as [attestation_mixed_hermetic_1]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	attestation_mixed_hermetic_2 := json.patch(
		{"statement": {
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": {
				"buildType": lib.tekton_pipeline_run,
				"buildConfig": {"tasks": [task1, task2]},
			},
		}},
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
	assertions.assert_equal_results(expected_mixed_hermetic_2, hermetic_task.deny) with input.attestations as [attestation_mixed_hermetic_2]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	_base_mixed_1 := tekton_test.slsav1_task("buildah")
	slsav1_task1_mixed = tekton_test.with_params(
		_base_mixed_1,
		[
			{"name": "HERMETIC", "value": "true"},
			{"name": "enable-hermeto-proxy", "value": "true"},
		],
	)

	_base_mixed_2 := tekton_test.slsav1_task("run-script-oci-ta")
	slsav1_task2_mixed = tekton_test.with_params(
		_base_mixed_2,
		[{
			"name": "HERMETIC",
			"value": "false",
		}],
	)

	slsav1_attestation_mixed_hermetic := tekton_test.slsav1_attestation([slsav1_task1_mixed, slsav1_task2_mixed])

	# regal ignore:line-length
	assertions.assert_equal_results(expected_mixed_hermetic_2, hermetic_task.deny) with input.attestations as [slsav1_attestation_mixed_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	attestation_non_hermetic := json.patch(
		{"statement": {
			"predicateType": "https://slsa.dev/provenance/v0.2",
			"predicate": {
				"buildType": lib.tekton_pipeline_run,
				"buildConfig": {"tasks": [task1, task2]},
			},
		}},
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
	assertions.assert_equal_results(expected_non_hermetic, hermetic_task.deny) with input.attestations as [attestation_non_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah", "run-script-oci-ta"]

	_base_non_hermetic_1 := tekton_test.slsav1_task("buildah")
	slsav1_task1_non_hermetic = tekton_test.with_params(
		_base_non_hermetic_1,
		[{
			"name": "HERMETIC",
			"value": "false",
		}],
	)

	_base_non_hermetic_2 := tekton_test.slsav1_task("run-script-oci-ta")
	slsav1_task2_non_hermetic = tekton_test.with_params(
		_base_non_hermetic_2,
		[{
			"name": "HERMETIC",
			"value": "false",
		}],
	)

	slsav1_attestation_non_hermetic := tekton_test.slsav1_attestation([
		slsav1_task1_non_hermetic,
		slsav1_task2_non_hermetic,
	])

	# regal ignore:line-length
	assertions.assert_equal_results(expected_non_hermetic, hermetic_task.deny) with input.attestations as [slsav1_attestation_non_hermetic]
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

test_hermetic_task_with_proxy_enabled if {
	# Hermetic task with proxy enabled - should pass
	_task_base := tekton_test.slsav1_task("buildah")
	slsav1_task = tekton_test.with_params(
		_task_base,
		[
			{"name": "HERMETIC", "value": "true"},
			{"name": "enable-hermeto-proxy", "value": "true"},
		],
	)

	slsav1_attestation := tekton_test.slsav1_attestation([slsav1_task])
	assertions.assert_empty(hermetic_task.deny) with input.attestations as [slsav1_attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah"]

	# v0.2 attestation
	assertions.assert_empty(hermetic_task.deny) with input.attestations as [_good_attestation_with_proxy]
		with data.rule_data.required_hermetic_tasks as ["buildah"]
}

test_hermetic_task_without_proxy if {
	expected := {{
		"code": "hermetic_task.hermeto_proxy_enabled",
		"msg": "Task 'buildah' is hermetic but does not have the enable-hermeto-proxy parameter set to true",
	}}

	# v0.2: hermetic but no proxy param
	# regal ignore:line-length
	no_proxy := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/0/invocation/parameters/enable-hermeto-proxy"])
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [no_proxy]
		with data.rule_data.required_hermetic_tasks as ["buildah"]

	# v0.2: hermetic with proxy set to false
	proxy_false := json.patch(_good_attestation, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/enable-hermeto-proxy",
		"value": "false",
	}])
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [proxy_false]
		with data.rule_data.required_hermetic_tasks as ["buildah"]

	# slsa v1: hermetic but no proxy param
	_task_base := tekton_test.slsav1_task("buildah")
	slsav1_task = tekton_test.with_params(
		_task_base,
		[{"name": "HERMETIC", "value": "true"}],
	)
	slsav1_attestation := tekton_test.slsav1_attestation([slsav1_task])
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [slsav1_attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah"]

	# slsa v1: hermetic with proxy set to false
	slsav1_task_proxy_false = tekton_test.with_params(
		_task_base,
		[
			{"name": "HERMETIC", "value": "true"},
			{"name": "enable-hermeto-proxy", "value": "false"},
		],
	)
	slsav1_att_proxy_false := tekton_test.slsav1_attestation([slsav1_task_proxy_false])
	assertions.assert_equal_results(expected, hermetic_task.deny) with input.attestations as [slsav1_att_proxy_false]
		with data.rule_data.required_hermetic_tasks as ["buildah"]
}

test_non_hermetic_task_no_proxy_required if {
	# Non-hermetic task without proxy - should pass (no proxy violation)
	_task_base := tekton_test.slsav1_task("buildah")
	slsav1_task_not_hermetic = tekton_test.with_params(
		_task_base,
		[{"name": "HERMETIC", "value": "false"}],
	)
	slsav1_attestation := tekton_test.slsav1_attestation([slsav1_task_not_hermetic])

	# The hermetic rule will fire, but the proxy rule should not
	results_no_proxy := hermetic_task.deny with input.attestations as [slsav1_attestation]
		with data.rule_data.required_hermetic_tasks as ["buildah"]

	not _has_proxy_violation(results_no_proxy)

	# Hermetic task without proxy - proxy violation should be present
	slsav1_task_hermetic = tekton_test.with_params(
		_task_base,
		[{"name": "HERMETIC", "value": "true"}],
	)
	slsav1_attestation_hermetic := tekton_test.slsav1_attestation([slsav1_task_hermetic])
	results_with_proxy := hermetic_task.deny with input.attestations as [slsav1_attestation_hermetic]
		with data.rule_data.required_hermetic_tasks as ["buildah"]

	_has_proxy_violation(results_with_proxy)
}

test_task_has_proxy_enabled if {
	task_with_proxy := tekton_test.resolved_slsav1_task(
		"some-task",
		[{"name": "enable-hermeto-proxy", "value": "true"}],
		[],
	)
	hermetic_task._task_has_proxy_enabled(task_with_proxy)

	task_proxy_false := tekton_test.resolved_slsav1_task(
		"some-task",
		[{"name": "enable-hermeto-proxy", "value": "false"}],
		[],
	)
	not hermetic_task._task_has_proxy_enabled(task_proxy_false)

	task_no_proxy := tekton_test.resolved_slsav1_task("some-task", [], [])
	not hermetic_task._task_has_proxy_enabled(task_no_proxy)
}

test_proxy_rule_data_validation if {
	# Valid data - no errors
	assertions.assert_empty(hermetic_task.deny) with data.rule_data as {
		"proxy_enabled_purl_types": ["maven", "npm"],
		"allowed_proxy_url_patterns": {"maven": ["^https://proxy\\.example\\.com/.*"]},
	}

	# Invalid proxy_enabled_purl_types: wrong type
	d_bad_purl_types := {
		"proxy_enabled_purl_types": [1, "maven", "maven"],
		"allowed_proxy_url_patterns": {},
	}
	expected_bad_purl_types := {
		{
			"code": "hermetic_task.proxy_rule_data_format",
			# regal ignore:line-length
			"msg": "Rule data proxy_enabled_purl_types has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "hermetic_task.proxy_rule_data_format",
			# regal ignore:line-length
			"msg": "Rule data proxy_enabled_purl_types has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(expected_bad_purl_types, hermetic_task.deny) with data.rule_data as d_bad_purl_types

	# Invalid allowed_proxy_url_patterns: wrong value type
	d_bad_patterns := {
		"proxy_enabled_purl_types": [],
		"allowed_proxy_url_patterns": {"maven": "not-an-array"},
	}
	expected_bad_patterns := {{
		"code": "hermetic_task.proxy_rule_data_format",
		# regal ignore:line-length
		"msg": "Rule data allowed_proxy_url_patterns has unexpected format: maven: Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(expected_bad_patterns, hermetic_task.deny) with data.rule_data as d_bad_patterns

	# Invalid regex in allowed_proxy_url_patterns
	d_bad_regex := {
		"proxy_enabled_purl_types": [],
		"allowed_proxy_url_patterns": {"maven": ["(?=a)?b"]},
	}
	expected_bad_regex := {{
		"code": "hermetic_task.proxy_rule_data_format",
		"msg": "\"(?=a)?b\" is not a valid regular expression for PURL type \"maven\"",
		"severity": "failure",
	}}
	assertions.assert_equal_results(expected_bad_regex, hermetic_task.deny) with data.rule_data as d_bad_regex
}

_has_proxy_violation(results) if {
	some result in results
	result.code == "hermetic_task.hermeto_proxy_enabled"
}

_good_attestation_with_proxy := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"results": [
				{"name": "IMAGE_URL", "value": "registry/repo"},
				{"name": "IMAGE_DIGEST", "value": "digest"},
			],
			# regal ignore:line-length
			"ref": {"kind": "Task", "name": "buildah", "bundle": "reg.img/spam@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
			"invocation": {"parameters": {"HERMETIC": "true", "enable-hermeto-proxy": "true"}},
		}]},
	},
}}

_good_attestation := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"results": [
				{"name": "IMAGE_URL", "value": "registry/repo"},
				{"name": "IMAGE_DIGEST", "value": "digest"},
			],
			# regal ignore:line-length
			"ref": {"kind": "Task", "name": "buildah", "bundle": "reg.img/spam@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
			"invocation": {"parameters": {"HERMETIC": "true", "enable-hermeto-proxy": "true"}},
		}]},
	},
}}
