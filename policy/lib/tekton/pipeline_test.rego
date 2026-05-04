package lib.tekton_test

import rego.v1

import data.lib.assertions
import data.lib.tekton

test_pipeline_label_selectors_build_task_slsa_v1_0 if {
	task_base := slsav1_task("build-container")
	task_w_labels = with_labels(task_base, {tekton.task_label: "generic"})
	task_full = with_results(
		task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	attestation := slsav1_attestation_full(
		[task_full],
		{tekton.pipeline_label: "ignored"},
		{},
	)

	assertions.assert_equal(tekton.pipeline_label_selectors(attestation), {"generic"})
}

test_pipeline_label_selectors_build_task_slsa_v0_2 if {
	task := {
		"ref": {"name": "build-container", "kind": "Task"},
		"results": [
			{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
			# regal ignore:line-length
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
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

	assertions.assert_equal(tekton.pipeline_label_selectors(attestation), {"generic"})
}

test_pipeline_label_selectors_pipeline_run_slsa_v1_0 if {
	attestation := json.patch(
		slsav1_attestation([]),
		[{
			"op": "add",
			"path": "/statement/predicate/buildDefinition/internalParameters",
			"value": {"labels": {tekton.pipeline_label: "generic"}},
		}],
	)

	assertions.assert_equal(tekton.pipeline_label_selectors(attestation), {"generic"})
}

test_pipeline_label_selectors_pipeline_run_slsa_v0_2 if {
	task := {
		"ref": {"name": "build-container", "kind": "Task"},
		"results": [
			{"name": "IMAGE_URL", "type": "string", "value": "localhost:5000/repo:latest"},
			# regal ignore:line-length
			{"name": "IMAGE_DIGEST", "type": "string", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	}

	attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildConfig": {"tasks": [task]},
			"invocation": {"environment": {"labels": {tekton.pipeline_label: "generic"}}},
		},
	}}

	assertions.assert_equal(tekton.pipeline_label_selectors(attestation), {"generic"})
}

test_pipeline_label_selectors_pipeline_definition if {
	pipeline := {"metadata": {"labels": {tekton.pipeline_label: "generic"}}}
	assertions.assert_equal(tekton.pipeline_label_selectors(pipeline), {"generic"})
}

test_fbc_pipeline_label_selectors if {
	image := {"config": {"Labels": {"operators.operatorframework.io.index.configs.v1": "/configs"}}}
	assertions.assert_equal(tekton.pipeline_label_selectors({}), {"fbc"}) with input.image as image
}

test_pipeline_label_selectors_multi_build_type_slsa_v1_0 if {
	docker_task_base := slsav1_task("build-container")
	docker_task_w_labels := with_labels(docker_task_base, {tekton.task_label: "docker"})
	docker_task := with_results(
		docker_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	bundle_task_base := slsav1_task("build-tekton-bundle")
	bundle_task_w_labels := with_labels(bundle_task_base, {tekton.task_label: "tkn-bundle"})
	bundle_task := with_results(
		bundle_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/bundle:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:def0000000000000000000000000000000000000000000000000000000000def"},
		],
	)

	attestation := slsav1_attestation_full(
		[docker_task, bundle_task],
		{tekton.pipeline_label: "ignored"},
		{},
	)

	assertions.assert_equal(tekton.pipeline_label_selectors(attestation), {"docker", "tkn-bundle"})
}

test_required_task_list_multi_type_union if {
	docker_task_base := slsav1_task("build-container")
	docker_task_w_labels := with_labels(docker_task_base, {tekton.task_label: "docker"})
	docker_task := with_results(
		docker_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	bundle_task_base := slsav1_task("build-tekton-bundle")
	bundle_task_w_labels := with_labels(bundle_task_base, {tekton.task_label: "tkn-bundle"})
	bundle_task := with_results(
		bundle_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/bundle:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:def0000000000000000000000000000000000000000000000000000000000def"},
		],
	)

	attestation := slsav1_attestation_full(
		[docker_task, bundle_task],
		{},
		{},
	)

	pipeline_required_tasks := {
		"docker": [{
			"effective_on": "2024-01-01T00:00:00Z",
			"tasks": ["buildah", "clair-scan", "git-clone"],
		}],
		"tkn-bundle": [{
			"effective_on": "2024-06-01T00:00:00Z",
			"tasks": ["tkn-build", "clair-scan"],
		}],
	}

	result := tekton.latest_required_pipeline_tasks(attestation) with data["pipeline-required-tasks"] as pipeline_required_tasks

	# Union of tasks from both types (deduplicated)
	assertions.assert_equal(result.tasks, {"buildah", "clair-scan", "git-clone", "tkn-build"})

	# max(effective_on) across types
	assertions.assert_equal(result.effective_on, "2024-06-01T00:00:00Z")
}

test_required_task_list_missing_type_skipped if {
	docker_task_base := slsav1_task("build-container")
	docker_task_w_labels := with_labels(docker_task_base, {tekton.task_label: "docker"})
	docker_task := with_results(
		docker_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	bundle_task_base := slsav1_task("build-tekton-bundle")
	bundle_task_w_labels := with_labels(bundle_task_base, {tekton.task_label: "tkn-bundle"})
	bundle_task := with_results(
		bundle_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/bundle:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:def0000000000000000000000000000000000000000000000000000000000def"},
		],
	)

	attestation := slsav1_attestation_full(
		[docker_task, bundle_task],
		{},
		{},
	)

	# Only docker exists in data, tkn-bundle does not
	pipeline_required_tasks := {"docker": [{
		"effective_on": "2024-01-01T00:00:00Z",
		"tasks": ["buildah", "git-clone"],
	}]}

	result := tekton.latest_required_pipeline_tasks(attestation) with data["pipeline-required-tasks"] as pipeline_required_tasks

	# Only docker tasks returned, tkn-bundle silently skipped
	assertions.assert_equal(result.tasks, {"buildah", "git-clone"})
	assertions.assert_equal(result.effective_on, "2024-01-01T00:00:00Z")
}

test_required_task_list_all_types_missing if {
	docker_task_base := slsav1_task("build-container")
	docker_task_w_labels := with_labels(docker_task_base, {tekton.task_label: "docker"})
	docker_task := with_results(
		docker_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	attestation := slsav1_attestation_full(
		[docker_task],
		{},
		{},
	)

	# No matching type in data
	pipeline_required_tasks := {"fbc": [{
		"effective_on": "2024-01-01T00:00:00Z",
		"tasks": ["fbc-validation"],
	}]}

	# required_task_list should be undefined (no matching selectors)
	not tekton.required_task_list(attestation) with data["pipeline-required-tasks"] as pipeline_required_tasks
}

test_current_required_pipeline_tasks_multi_type if {
	docker_task_base := slsav1_task("build-container")
	docker_task_w_labels := with_labels(docker_task_base, {tekton.task_label: "docker"})
	docker_task := with_results(
		docker_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	bundle_task_base := slsav1_task("build-tekton-bundle")
	bundle_task_w_labels := with_labels(bundle_task_base, {tekton.task_label: "tkn-bundle"})
	bundle_task := with_results(
		bundle_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/bundle:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:def0000000000000000000000000000000000000000000000000000000000def"},
		],
	)

	attestation := slsav1_attestation_full(
		[docker_task, bundle_task],
		{},
		{},
	)

	pipeline_required_tasks := {
		"docker": [{
			"effective_on": "2024-01-01T00:00:00Z",
			"tasks": ["buildah", "git-clone"],
		}],
		"tkn-bundle": [
			{
				"effective_on": "2024-06-01T00:00:00Z",
				"tasks": ["tkn-build"],
			},
			{
				"effective_on": "2099-01-01T00:00:00Z",
				"tasks": ["tkn-build", "future-task"],
			},
		],
	}

	result := tekton.current_required_pipeline_tasks(attestation) with data["pipeline-required-tasks"] as pipeline_required_tasks

	# most_current excludes the future entry (2099), so tkn-bundle resolves to 2024-06-01
	assertions.assert_equal(result.tasks, {"buildah", "git-clone", "tkn-build"})
	assertions.assert_equal(result.effective_on, "2024-06-01T00:00:00Z")
}

test_required_task_list_multi_type_concatenation if {
	docker_task_base := slsav1_task("build-container")
	docker_task_w_labels := with_labels(docker_task_base, {tekton.task_label: "docker"})
	docker_task := with_results(
		docker_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	bundle_task_base := slsav1_task("build-tekton-bundle")
	bundle_task_w_labels := with_labels(bundle_task_base, {tekton.task_label: "tkn-bundle"})
	bundle_task := with_results(
		bundle_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/bundle:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:def0000000000000000000000000000000000000000000000000000000000def"},
		],
	)

	attestation := slsav1_attestation_full(
		[docker_task, bundle_task],
		{},
		{},
	)

	pipeline_required_tasks := {
		"docker": [{
			"effective_on": "2024-01-01T00:00:00Z",
			"tasks": ["buildah"],
		}],
		"tkn-bundle": [{
			"effective_on": "2024-06-01T00:00:00Z",
			"tasks": ["tkn-build"],
		}],
	}

	result := tekton.required_task_list(attestation) with data["pipeline-required-tasks"] as pipeline_required_tasks

	# Concatenated raw entries from both types
	count(result) == 2
}

test_latest_required_pipeline_tasks_single_type if {
	task_base := slsav1_task("build-container")
	task_w_labels := with_labels(task_base, {tekton.task_label: "docker"})
	task_full := with_results(
		task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	attestation := slsav1_attestation_full(
		[task_full],
		{},
		{},
	)

	pipeline_required_tasks := {"docker": [{
		"effective_on": "2024-01-01T00:00:00Z",
		"tasks": ["buildah", "clair-scan", "git-clone"],
	}]}

	result := tekton.latest_required_pipeline_tasks(attestation) with data["pipeline-required-tasks"] as pipeline_required_tasks

	assertions.assert_equal(result.tasks, {"buildah", "clair-scan", "git-clone"})
	assertions.assert_equal(result.effective_on, "2024-01-01T00:00:00Z")
}

test_latest_required_pipeline_tasks_multi_time_entries if {
	docker_task_base := slsav1_task("build-container")
	docker_task_w_labels := with_labels(docker_task_base, {tekton.task_label: "docker"})
	docker_task := with_results(
		docker_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/repo:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		],
	)

	bundle_task_base := slsav1_task("build-tekton-bundle")
	bundle_task_w_labels := with_labels(bundle_task_base, {tekton.task_label: "tkn-bundle"})
	bundle_task := with_results(
		bundle_task_w_labels,
		[
			{"name": "IMAGE_URL", "value": "localhost:5000/bundle:latest"},
			{"name": "IMAGE_DIGEST", "value": "sha256:def0000000000000000000000000000000000000000000000000000000000def"},
		],
	)

	attestation := slsav1_attestation_full(
		[docker_task, bundle_task],
		{},
		{},
	)

	pipeline_required_tasks := {
		"docker": [
			{
				"effective_on": "2024-01-01T00:00:00Z",
				"tasks": ["buildah"],
			},
			{
				"effective_on": "2024-06-01T00:00:00Z",
				"tasks": ["buildah", "clair-scan"],
			},
		],
		"tkn-bundle": [
			{
				"effective_on": "2024-03-01T00:00:00Z",
				"tasks": ["tkn-build"],
			},
			{
				"effective_on": "2024-09-01T00:00:00Z",
				"tasks": ["tkn-build", "tkn-lint"],
			},
		],
	}

	result := tekton.latest_required_pipeline_tasks(attestation) with data["pipeline-required-tasks"] as pipeline_required_tasks

	# newest picks the latest entry per type: docker=2024-06-01, tkn-bundle=2024-09-01
	assertions.assert_equal(result.tasks, {"buildah", "clair-scan", "tkn-build", "tkn-lint"})

	# max(effective_on) across resolved types
	assertions.assert_equal(result.effective_on, "2024-09-01T00:00:00Z")
}
