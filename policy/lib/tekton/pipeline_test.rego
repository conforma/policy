package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_pipeline_label_selector_build_task_slsa_v1_0 if {
	task := json.patch(
		slsav1_task("build-container"),
		[
			{"op": "add", "path": "/metadata/labels", "value": {tekton.task_label: "generic"}},
			{"op": "add", "path": "/metadata/labels/tekton.dev/pipelineTask", "value": "build-container"},
		],
	)

	byproducts := [
		{"name": "taskRunResults/build-container/IMAGE_URL", "content": base64.encode("localhost:5000/repo:latest")},
		{"name": "taskRunResults/build-container/IMAGE_DIGEST", "content": base64.encode("sha256:abc")},
	]

	attestation := json.patch(
		slsav1_attestation_with_params_and_byproducts([task], [], byproducts),
		[{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/internalParameters",
			"value": {"labels": {tekton.pipeline_label: "ignored"}},
		}],
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
