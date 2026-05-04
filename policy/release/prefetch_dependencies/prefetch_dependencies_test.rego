package prefetch_dependencies_test

import rego.v1

import data.lib
import data.lib.assertions
import data.lib.tekton_test
import data.prefetch_dependencies

test_mode_permissive_violation if {
	expected := {{
		"code": "prefetch_dependencies.mode_not_permissive",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Task 'prefetch-dependencies' was invoked with mode parameter set to 'permissive'",
	}}
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies", "permissive", "true")
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies", "permissive", "true")
}

test_mode_not_permissive_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies", "strict", "true")
	assertions.assert_empty(prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies", "strict", "true")
}

test_missing_mode_param_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation_without_mode("prefetch-dependencies")
	assertions.assert_empty(prefetch_dependencies.deny) with input as _slsav1_attestation_without_mode("prefetch-dependencies")
}

test_task_not_present_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("some-other-task", "permissive", "true")
	assertions.assert_empty(prefetch_dependencies.deny) with input as _slsav1_attestation("some-other-task", "permissive", "true")
}

test_oci_ta_mode_permissive_violation if {
	expected := {{
		"code": "prefetch_dependencies.mode_not_permissive",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Task 'prefetch-dependencies' was invoked with mode parameter set to 'permissive'",
	}}
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies-oci-ta", "permissive", "true")
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies-oci-ta", "permissive", "true")
}

test_oci_ta_mode_not_permissive_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies-oci-ta", "strict", "true")
	assertions.assert_empty(prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies-oci-ta", "strict", "true")
}

test_proxy_disabled_violation if {
	expected := {{
		"code": "prefetch_dependencies.package_registry_proxy_enabled",
		"effective_on": "2026-06-01T00:00:00Z",
		"msg": "Task 'prefetch-dependencies' does not have the enable-package-registry-proxy parameter set to true",
	}}
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies", "strict", "false")
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies", "strict", "false")
}

test_proxy_enabled_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies", "strict", "true")
	assertions.assert_empty(prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies", "strict", "true")
}

test_missing_proxy_param_violation if {
	expected := {{
		"code": "prefetch_dependencies.package_registry_proxy_enabled",
		"effective_on": "2026-06-01T00:00:00Z",
		"msg": "Task 'prefetch-dependencies' does not have the enable-package-registry-proxy parameter set to true",
	}}
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _attestation_without_proxy("prefetch-dependencies")
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _slsav1_attestation_without_proxy("prefetch-dependencies")
}

test_proxy_unrelated_task_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("some-other-task", "strict", "false")
	assertions.assert_empty(prefetch_dependencies.deny) with input as _slsav1_attestation("some-other-task", "strict", "false")
}

test_oci_ta_proxy_disabled_violation if {
	expected := {{
		"code": "prefetch_dependencies.package_registry_proxy_enabled",
		"effective_on": "2026-06-01T00:00:00Z",
		"msg": "Task 'prefetch-dependencies-oci-ta' does not have the enable-package-registry-proxy parameter set to true",
	}}
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies-oci-ta", "strict", "false")
	assertions.assert_equal_results(expected, prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies-oci-ta", "strict", "false")
}

test_oci_ta_proxy_enabled_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies-oci-ta", "strict", "true")
	assertions.assert_empty(prefetch_dependencies.deny) with input as _slsav1_attestation("prefetch-dependencies-oci-ta", "strict", "true")
}

_make_attestation(task_name, params) := {"attestations": [{"statement": {
	"_type": "https://in-toto.io/Statement/v0.1",
	"subject": [{"name": "registry.redhat.io/ubi8/ubi:latest"}],
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": task_name,
			"ref": {
				"name": task_name,
				"kind": "Task",
			},
			"invocation": {"parameters": params},
		}]},
	},
}}]}

_attestation(task_name, mode, proxy) := _make_attestation(task_name, {
	"input": "$(params.prefetch-input)",
	"mode": mode,
	"enable-package-registry-proxy": proxy,
})

_attestation_without_proxy(task_name) := _make_attestation(task_name, {
	"input": "$(params.prefetch-input)",
	"mode": "strict",
})

_attestation_without_mode(task_name) := _make_attestation(task_name, {
	"input": "$(params.prefetch-input)",
	"enable-package-registry-proxy": "true",
})

_slsav1_make_attestation(task_name, params) := {"attestations": [att]} if {
	_base := tekton_test.slsav1_task(task_name)
	task := tekton_test.with_params(_base, params)
	att := tekton_test.slsav1_attestation([task])
}

_slsav1_attestation(task_name, mode, proxy) := _slsav1_make_attestation(task_name, [
	{"name": "mode", "value": mode},
	{"name": "enable-package-registry-proxy", "value": proxy},
])

_slsav1_attestation_without_proxy(task_name) := _slsav1_make_attestation(task_name, [{"name": "mode", "value": "strict"}])

_slsav1_attestation_without_mode(task_name) := _slsav1_make_attestation(task_name, [{"name": "enable-package-registry-proxy", "value": "true"}])
