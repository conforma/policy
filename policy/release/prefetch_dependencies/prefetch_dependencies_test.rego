package prefetch_dependencies_test

import rego.v1

import data.lib
import data.lib.assertions
import data.prefetch_dependencies

test_mode_permissive_violation if {
	assertions.assert_equal_results(prefetch_dependencies.deny, {{
		"code": "prefetch_dependencies.mode_not_permissive",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Task 'prefetch-dependencies' was invoked with mode parameter set to 'permissive'",
	}}) with input as _attestation("prefetch-dependencies", "permissive")
}

test_mode_not_permissive_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies", "strict")
}

test_missing_mode_param_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation_without_mode("prefetch-dependencies")
}

test_task_not_present_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("some-other-task", "permissive")
}

test_oci_ta_mode_permissive_violation if {
	assertions.assert_equal_results(prefetch_dependencies.deny, {{
		"code": "prefetch_dependencies.mode_not_permissive",
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Task 'prefetch-dependencies' was invoked with mode parameter set to 'permissive'",
	}}) with input as _attestation("prefetch-dependencies-oci-ta", "permissive")
}

test_oci_ta_mode_not_permissive_pass if {
	assertions.assert_empty(prefetch_dependencies.deny) with input as _attestation("prefetch-dependencies-oci-ta", "strict")
}

# Helper to create attestation with mode parameter
_attestation(task_name, mode) := {"attestations": [{"statement": {
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
			"invocation": {"parameters": {
				"input": "$(params.prefetch-input)",
				"mode": mode,
			}},
		}]},
	},
}}]}

# Helper to create attestation without mode parameter
_attestation_without_mode(task_name) := {"attestations": [{"statement": {
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
			"invocation": {"parameters": {"input": "$(params.prefetch-input)"}},
		}]},
	},
}}]}
