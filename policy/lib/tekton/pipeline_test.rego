package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_pipeline_label_selector_build_task_slsa_v1_0 if {
	task_base := slsav1_task("build-container")
	task_w_labels = with_labels(task_base, {tekton.task_label: "generic"})
	task_full = with_results(
		task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc"},
		],
	)

	attestation := slsav1_attestation_full(
		[task_full],
		{tekton.pipeline_label: "ignored"},
		{},
	)

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_build_task_slsa_v0_2 if {
	task := {
		"ref": {"name": "build-container", "kind": "Task"},
		"results": [
			{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
		],
		"invocation": {"environment": {"labels": {tekton.task_label: "generic"}}},
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildConfig": {"tasks": [task]},
			"invocation": {"environment": {"labels": {tekton.pipeline_label: "ignored"}}},
		},
	}}

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_run_slsa_v1_0 if {
	attestation := json.patch(
		slsav1_attestation([]),
		[{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/internalParameters",
			"value": {"labels": {tekton.pipeline_label: "generic"}},
		}],
	)

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_run_slsa_v0_2 if {
	task := {
		"ref": {"name": "build-container", "kind": "Task"},
		"results": [
			{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc"},
		],
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildConfig": {"tasks": [task]},
			"invocation": {"environment": {"labels": {tekton.pipeline_label: "generic"}}},
		},
	}}

	lib.assert_equal(tekton.pipeline_label_selector(attestation), "generic")
}

test_pipeline_label_selector_pipeline_definition if {
	pipeline := {"metadata": {"labels": {tekton.pipeline_label: "generic"}}}
	lib.assert_equal(tekton.pipeline_label_selector(pipeline), "generic")
}

test_fbc_pipeline_label_selector if {
	image := {"config": {"Labels": {"operators.operatorframework.io.index.configs.v1": "/configs"}}}
	lib.assert_equal(tekton.pipeline_label_selector({}), "fbc") with input.image as image
}
