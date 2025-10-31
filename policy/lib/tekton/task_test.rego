package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_latest_required_tasks if {
	expected := [t | some t in _expected_latest.tasks]
	lib.assert_equal(
		expected,
		tekton.latest_required_default_tasks.tasks,
	) with data["required-tasks"] as _time_based_required_tasks
}

test_current_required_tasks if {
	expected := [t | some t in _expected_current.tasks]
	lib.assert_equal(
		expected,
		tekton.current_required_default_tasks.tasks,
	) with data["required-tasks"] as _time_based_required_tasks
}

test_tasks_from_attestation if {
	git_clone := {"name": "ignored", "ref": {"name": "git-clone"}}
	buildah := {"name": "ignored", "ref": {"name": "buildah"}}

	attestation := {"statement": {"predicate": {"buildConfig": {"tasks": [git_clone, buildah]}}}}
	expected := {
		{"name": "ignored", "ref": {"name": "git-clone"}, "params": [], "results": []},
		{"name": "ignored", "ref": {"name": "buildah"}, "params": [], "results": []},
	}
	lib.assert_equal(expected, tekton.tasks(attestation))
}

test_tasks_from_slsav1_tekton_attestation if {
	task_params := [
		{
			"name": "input",
			"value": "$(params.prefetch-input)",
		},
		{
			"name": "SOURCE_ARTIFACT",
			"value": "$(tasks.another-task.results.SOURCE_ARTIFACT)",
		},
		{
			"name": "ociStorage",
			"value": "$(params.output-image).prefetch",
		},
	]
	task := slsav1_task_with_params("test-task", "test-task", task_params)

	att_params := [
		{
			"name": "prefetch-input",
			"value": "true",
		},
		{
			"name": "output-image",
			"value": "quay.io/test-registry/img:sha256",
		},
	]

	att_byproducts := [{
		"name": "taskRunResults/another-task/SOURCE_ARTIFACT",
		"content": "cXVheS5pby9yZWRoYXQtYXBwc3R1ZGlvL2hhY2JzLXRlc3Q6djEuMS45QHNoYTI1Njo4NjY2NzVlZTMwNjRjZjQ3Njg2OTFlY2NhNDc4MDYzY2UxMmYwNTU2ZmI5ZDRmMjRjYTk1Yzk4NjY0ZmZiZDQz", # regal ignore:line-length
	}]

	attestation := slsav1_attestation_with_params_and_byproducts([task], att_params, att_byproducts)

	expected_task := {
		"name": "test-task",
		"params": [
			{
				"name": "input",
				"value": "true",
			},
			{
				"name": "SOURCE_ARTIFACT",
				"value": "quay.io/redhat-appstudio/hacbs-test:v1.1.9@sha256:866675ee3064cf4768691ecca478063ce12f0556fb9d4f24ca95c98664ffbd43", # regal ignore:line-length
			},
			{
				"name": "ociStorage",
				"value": "quay.io/test-registry/img:sha256.prefetch",
			},
		],
		"results": [],
		"taskRef": {
			"params": [
				{
					"name": "name",
					"value": "test-task",
				},
				{
					"name": "bundle",
					"value": "test-task-bundle",
				},
				{
					"name": "kind",
					"value": "task",
				},
			],
			"resolver": "bundles",
		},
		"workspaces": [{
			"name": "test-task",
			"workspace": "test-task-workspace",
		}],
	}

	tasks := tekton.tasks(attestation)
	lib.assert_equal({expected_task}, tasks)
}

test_tasks_from_pipeline if {
	git_clone := {"taskRef": {"name": "git-clone"}}
	buildah := {"taskRef": {"name": "buildah"}}
	summary := {"taskRef": {"name": "summary"}}
	pipeline := {
		"kind": "Pipeline",
		"spec": {
			"tasks": [git_clone, buildah],
			"finally": [summary],
		},
	}
	expected := {
		{"taskRef": {"name": "git-clone"}, "params": [], "results": []},
		{"taskRef": {"name": "buildah"}, "params": [], "results": []},
		{"taskRef": {"name": "summary"}, "params": [], "results": []},
	}
	lib.assert_equal(expected, tekton.tasks(pipeline))
}

test_tasks_from_partial_pipeline if {
	lib.assert_empty(tekton.tasks({"kind": "Pipeline"}))
	lib.assert_empty(tekton.tasks({"kind": "Pipeline", "spec": {}}))

	git_clone := {"taskRef": {"name": "git-clone"}}
	expected := {{"taskRef": {"name": "git-clone"}, "params": [], "results": []}}
	lib.assert_equal(expected, tekton.tasks({"kind": "Pipeline", "spec": {"tasks": [git_clone]}}))
	lib.assert_equal(expected, tekton.tasks({"kind": "Pipeline", "spec": {"finally": [git_clone]}}))
}

test_tasks_not_found if {
	lib.assert_empty(tekton.tasks({}))
}

test_task_param if {
	task := {"params": [{"name": "NETWORK", "value": "none"}]}
	lib.assert_equal("none", tekton.task_param(task, "NETWORK"))
	not tekton.task_param(task, "missing")
}

test_task_result if {
	task := {"results": [{"name": "SPAM", "value": "maps"}]}
	lib.assert_equal("maps", tekton.task_result(task, "SPAM"))
	not tekton.task_result(task, "missing")

	slsav1_task := resolved_slsav1_task("task-name", [], [{"name": "SPAM", "value": "maps"}])
	lib.assert_equal("maps", tekton.task_result(slsav1_task, "SPAM"))
	not tekton.task_result(slsav1_task, "missing")
}

test_tasks_from_attestation_with_spam if {
	tasks := {
		{"ref": {"name": "git-clone", "kind": "Task", "bundle": _bundle}},
		_good_build_task,
		{
			"ref": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
			"invocation": {"parameters": {"SPAM": "MAPS"}},
		},
		{"ref": {"name": "summary", "kind": "Task", "bundle": _bundle}},
	}

	attestation := {"statement": {"predicate": {"buildConfig": {"tasks": tasks}}}}

	expected_tasks := {
		{"ref": {"name": "git-clone", "kind": "Task", "bundle": _bundle}, "params": [], "results": []},
		_good_build_task,
		{
			"ref": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
			"invocation": {"parameters": {"SPAM": "MAPS"}},
			"params": [],
			"results": [],
		},
		{"ref": {"name": "summary", "kind": "Task", "bundle": _bundle}, "params": [], "results": []},
	}
	lib.assert_equal(expected_tasks, tekton.tasks(attestation))
	# expected_names := {"git-clone", "buildah", "buildah[HERMETIC=true]", "weird", "weird[SPAM=MAPS]", "summary"}
	# lib.assert_equal(expected_names, tekton.tasks_names(attestation))
}

# regal ignore:rule-length
test_tasks_from_pipeline_with_spam if {
	pipeline := {
		"kind": "Pipeline",
		"spec": {
			"tasks": [
				{"taskRef": {"name": "git-clone", "kind": "Task", "bundle": _bundle}},
				{
					"taskRef": {"name": "buildah", "kind": "Task", "bundle": _bundle},
					"params": [{"name": "NETWORK", "value": "none"}],
				},
				{
					"taskRef": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
					"params": [{"name": "SPAM", "value": "MAPS"}],
				},
				{"taskRef": {"name": "ignored-bad-kind", "kind": "NotTask", "bundle": _bundle}},
			],
			"finally": [{"taskRef": {"name": "summary", "kind": "Task", "bundle": _bundle}}],
		},
	}

	expected_tasks := {
		{
			"taskRef": {"name": "git-clone", "kind": "Task", "bundle": _bundle},
			"params": [],
			"results": [],
		},
		{
			"taskRef": {"name": "buildah", "kind": "Task", "bundle": _bundle},
			"params": [{"name": "NETWORK", "value": "none"}],
			"results": [],
		},
		{
			"taskRef": {"name": "weird[food=spam]", "kind": "Task", "bundle": _bundle},
			"params": [{"name": "SPAM", "value": "MAPS"}],
			"results": [],
		},
		{
			"taskRef": {"name": "summary", "kind": "Task", "bundle": _bundle},
			"params": [],
			"results": [],
		},
	}
	lib.assert_equal(expected_tasks, tekton.tasks(pipeline))

	expected_names := {"git-clone", "buildah", "buildah[NETWORK=none]", "weird", "weird[SPAM=MAPS]", "summary"}
	lib.assert_equal(expected_names, tekton.tasks_names(pipeline))
}

test_build_task if {
	expected := [_good_build_task, _good_source_build_task]
	lib.assert_equal(expected, tekton.build_tasks(_good_attestation))
}

test_build_task_with_artifact_uri if {
	artifact_uri_result := json.patch(_good_attestation, [
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "ARTIFACT_URI",
		},
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1/name",
			"value": "ARTIFACT_DIGEST",
		},
	])
	count(tekton.build_tasks(artifact_uri_result)) == 2
}

test_build_task_with_artifact_output if {
	artifact_uri_result := json.patch(_good_attestation, [
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "ARTIFACT_OUTPUTS",
		},
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/value",
			"value": {"uri": "img1", "digest": "1234"},
		},
		{
			"op": "remove",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1",
		},
	])
	count(tekton.build_tasks(artifact_uri_result)) == 2
}

test_build_task_with_images if {
	artifact_uri_result := json.patch(_good_attestation, [
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "IMAGES",
		},
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/value",
			"value": "img1@sha256:digest1, img2@sha256:digest2",
		},
		{
			"op": "remove",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1",
		},
	])
	count(tekton.build_tasks(artifact_uri_result)) == 2
}

test_build_task_not_found if {
	missing_image_url := json.patch(_good_attestation, [
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/name",
			"value": "IMAGE_URL_SKIP",
		},
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/2/results/0/name",
			"value": "IMAGE_URL_SKIP",
		},
	])
	count(tekton.build_tasks(missing_image_url)) == 0

	missing_image_digest := json.patch(_good_attestation, [
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/0/results/1/name",
			"value": "IMAGE_DIGEST_SKIP",
		},
		{
			"op": "add",
			"path": "/statement/predicate/buildConfig/tasks/2/results/1/name",
			"value": "IMAGE_DIGEST_SKIP",
		},
	])
	count(tekton.build_tasks(missing_image_digest)) == 0

	missing_results := json.remove(_good_attestation, [
		"/statement/predicate/buildConfig/tasks/0/results",
		"/statement/predicate/buildConfig/tasks/2/results",
	])
	count(tekton.build_tasks(missing_results)) == 0
}

test_pre_build_tasks if {
	expected := [_pre_build_task]
	lib.assert_equal(expected, tekton.pre_build_tasks(_good_attestation))
}

test_multiple_build_tasks if {
	task1 := json.patch(_good_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "buildah-1",
	}])

	task2 := json.patch(_good_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "buildah-2",
	}])

	task3 := json.patch(_good_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "buildah-3",
	}])

	attestation3 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2, task3]},
	}}}

	count(tekton.build_tasks(attestation3)) == 3

	attestation2 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, _good_git_clone_task, task3]},
	}}}

	count(tekton.build_tasks(attestation2)) == 2
}

test_git_clone_task if {
	expected := _good_git_clone_task
	lib.assert_equal([expected], tekton.git_clone_tasks(_good_attestation))
}

test_git_clone_task_not_found if {
	missing_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/results/0/name",
		"value": "you-argh-el",
	}])
	count(tekton.git_clone_tasks(missing_url)) == 0

	missing_commit := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/results/1/name",
		"value": "bachelor",
	}])
	count(tekton.git_clone_tasks(missing_commit)) == 0

	missing_results := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/1/results"])
	count(tekton.git_clone_tasks(missing_results)) == 0
}

test_multiple_git_clone_tasks if {
	task1 := json.patch(_good_git_clone_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "git-clone-1",
	}])

	task2 := json.patch(_good_git_clone_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "git-clone-2",
	}])

	task3 := json.patch(_good_git_clone_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "git-clone-3",
	}])

	attestation3 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2, task3]},
	}}}

	count(tekton.git_clone_tasks(attestation3)) == 3

	attestation2 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, _good_build_task, task3]},
	}}}

	count(tekton.git_clone_tasks(attestation2)) == 2
}

test_source_build_task if {
	expected := _good_source_build_task
	lib.assert_equal([expected], tekton.source_build_tasks(_good_attestation))
}

test_source_build_task_not_found if {
	missing_image_url := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/2/results/0/name",
		"value": "ee-mah-gee-you-argh-el",
	}])
	count(tekton.source_build_tasks(missing_image_url)) == 0

	missing_image_digest := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/2/results/1/name",
		"value": "still-raw",
	}])
	count(tekton.source_build_tasks(missing_image_digest)) == 0

	missing_results := json.remove(_good_attestation, ["/statement/predicate/buildConfig/tasks/2/results"])
	count(tekton.source_build_tasks(missing_results)) == 0
}

test_multiple_source_build_tasks if {
	task1 := json.patch(_good_source_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "source-build-1",
	}])

	task2 := json.patch(_good_source_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "source-build-2",
	}])

	task3 := json.patch(_good_source_build_task, [{
		"op": "replace",
		"path": "/ref/name",
		"value": "source-build-3",
	}])

	attestation_with_3 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, task2, task3]},
	}}}

	count(tekton.source_build_tasks(attestation_with_3)) == 3

	attestation_with_2 := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task1, _good_build_task, task3]},
	}}}

	count(tekton.source_build_tasks(attestation_with_2)) == 2
}

test_task_data_bundle_ref if {
	lib.assert_equal(
		{
			"bundle": "bundle",
			"name": "ref-name",
		},
		tekton.task_data({
			"name": "name",
			"ref": {
				"name": "ref-name",
				"kind": "Task",
				"bundle": "bundle",
			},
		}),
	)
}

test_task_names_local if {
	task_params := [
		{
			"name": "DOCKERFILE",
			"value": "./image_with_labels/Dockerfile",
		},
		{
			"name": "IMAGE",
			"value": "quay.io/jstuart/hacbs-docker-build",
		},
	]
	task := resolved_slsav1_task("buildah", task_params, [])

	expected := {
		"buildah",
		"buildah[DOCKERFILE=./image_with_labels/Dockerfile]",
		"buildah[IMAGE=quay.io/jstuart/hacbs-docker-build]",
	}

	lib.assert_equal(expected, tekton.task_names(task))
}

test_task_data_no_bundle_ref if {
	lib.assert_equal({"name": "name"}, tekton.task_data({"ref": {"name": "name"}}))
}

test_missing_required_tasks_data if {
	lib.assert_equal(tekton.missing_required_tasks_data, true) with data["required-tasks"] as []
	lib.assert_equal(tekton.missing_required_tasks_data, false) with data["required-tasks"] as _time_based_required_tasks
}

test_task_step_image_ref if {
	lib.assert_equal(
		"redhat.io/openshift/rhel8@sha256:af7dd5b3b",
		tekton.task_step_image_ref({"name": "mystep", "imageID": "redhat.io/openshift/rhel8@sha256:af7dd5b3b"}),
	)
	lib.assert_equal(
		"redhat.io/openshift/rhel8@sha256:af7dd5b3b",
		tekton.task_step_image_ref({"environment": {"image": "redhat.io/openshift/rhel8@sha256:af7dd5b3b"}}),
	)
}

test_pipeline_task_slsav1 if {
	slsav1_task_spec := {"metadata": {
		"name": "clone-build-push-run-cb7ch-build-push",
		"labels": {
			"app.kubernetes.io/managed-by": "tekton-pipelines",
			"app.kubernetes.io/version": "0.5",
			"tekton.dev/memberOf": "tasks",
			"tekton.dev/pipeline": "clone-build-push-run-cb7ch",
			"tekton.dev/pipelineRun": "clone-build-push-run-cb7ch",
			"tekton.dev/pipelineTask": "build-push",
			"tekton.dev/task": "buildah",
		},
	}}
	lib.assert_equal(tekton.pipeline_task_name(slsav1_task_spec), "build-push")
	lib.assert_equal(tekton.pipeline_task_name(slsav1_task("my-pipeline")), "my-pipeline")
}

test_pipeline_task_slsav02 if {
	slsav02_inline_task_spec := {
		"name": "copy-settings",
		"after": ["clone-repository"],
		"ref": {},
	}
	lib.assert_equal(tekton.pipeline_task_name(slsav02_inline_task_spec), "copy-settings")

	task := {"name": "git-clone-p", "ref": {"name": "git-clone"}}
	lib.assert_equal(tekton.pipeline_task_name(task), "git-clone-p")
}

test_taskrun_labels_slsa02 if {
	task := {"invocation": {"environment": {"labels": {
		"l1": "v1",
		"l2": "v2",
	}}}}
	lib.assert_equal(tekton.task_labels(task), {"l1": "v1", "l2": "v2"})
}

test_taskrun_annotations_slsa02 if {
	task := {"invocation": {"environment": {"annotations": {
		"a1": "v1",
		"a2": "v2",
	}}}}
	lib.assert_equal(tekton.task_annotations(task), {"a1": "v1", "a2": "v2"})
}

test_taskrun_labels_slsa1 if {
	task := {"metadata": {"labels": {
		"l1": "v1",
		"l2": "v2",
	}}}
	lib.assert_equal(tekton.task_labels(task), {"l1": "v1", "l2": "v2"})
}

test_taskrun_annotations_slsa1 if {
	task := {"metadata": {"annotations": {
		"a1": "v1",
		"a2": "v2",
	}}}
	lib.assert_equal(tekton.task_annotations(task), {"a1": "v1", "a2": "v2"})
}

test_task_result_endswith if {
	results := [
		{
			"name": "ARTIFACT_URI",
			"value": "image1",
		},
		{
			"name": "ARTIFACT_DIGEST",
			"value": "1234",
		},
		{
			"name": "1234_ARTIFACT_URI",
			"value": "1234-image1",
		},
		{
			"name": "1234_ARTIFACT_DIGEST",
			"value": "1234-digest",
		},
	]
	task1 := resolved_slsav1_task("task1", [], results)
	lib.assert_equal(["1234-image1", "image1"], tekton.task_result_endswith(task1, "ARTIFACT_URI"))
}

_expected_latest := {
	"effective_on": "2099-01-02T00:00:00Z",
	"tasks": [
		"git-clone",
		"buildah",
		"conftest-clair",
		"label-check[POLICY_NAMESPACE=required_checks]",
		"label-check[POLICY_NAMESPACE=optional_checks]",
	],
}

_expected_current := {
	"effective_on": "2022-12-01T00:00:00Z",
	"tasks": [
		"git-clone",
		"buildah",
		"not-required-in-future",
		"label-check[POLICY_NAMESPACE=required_checks]",
		"label-check[POLICY_NAMESPACE=optional_checks]",
	],
}

_time_based_required_tasks := [
	_expected_latest,
	{
		"effective_on": "2099-01-01T00:00:00Z",
		"tasks": ["also-ignored"],
	},
	_expected_current,
	{
		"effective_on": "2022-01-01T00:00:00Z",
		"tasks": ["ignored"],
	},
]

_pre_build_task := {
	"results": [],
	"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": _bundle},
	"invocation": {"parameters": {"HERMETIC": "true"}},
}

_good_build_task := {
	"results": [
		{"name": "IMAGE_URL", "value": "registry/repo"},
		{"name": "IMAGE_DIGEST", "value": "digest"},
	],
	"ref": {"kind": "Task", "name": "buildah", "bundle": _bundle},
	"invocation": {"parameters": {"HERMETIC": "true"}},
}

_good_git_clone_task := {
	"results": [
		{"name": "url", "value": "https://forge/repo"},
		{"name": "commit", "value": "250e77f12a5ab6972a0895d290c4792f0a326ea8"},
	],
	"ref": {"kind": "Task", "name": "git-clone", "bundle": _bundle},
}

_good_source_build_task := {
	"results": [
		{"name": "SOURCE_IMAGE_URL", "value": "registry.local/repo"},
		{"name": "SOURCE_IMAGE_DIGEST", "value": "250e77f12a5ab6972a0895d290c4792f0a326ea8"},
	],
	"ref": {"kind": "Task", "name": "source-build", "bundle": _bundle},
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [_good_build_task, _good_git_clone_task, _good_source_build_task, _pre_build_task]},
}}}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

slsav1_task(name) := slsav1_task_with_params(name, name, [])

slsav1_task_with_params(name, ref_name, task_params) := {
	"name": name,
	"params": task_params,
	"taskRef": {
		"params": [
			{
				"name": "name",
				"value": ref_name,
			},
			{
				"name": "bundle",
				"value": concat("-", [name, "bundle"]),
			},
			{
				"name": "kind",
				"value": "task",
			},
		],
		"resolver": "bundles",
	},
	"workspaces": [{
		"name": name,
		"workspace": concat("-", [name, "workspace"]),
	}],
}

slsav1_attestation(tasks) := slsav1_attestation_with_params_and_byproducts(tasks, [], [])

slsav1_attestation_with_params_and_byproducts(tasks, att_params, att_byproducts) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {
		"buildDefinition": {
			"buildType": "https://tekton.dev/chains/v2/slsa-tekton",
			"externalParameters": {"runSpec": {
				"params": att_params,
				"pipelineSpec": {"tasks": tasks},
			}},
		},
		"runDetails": {"byproducts": att_byproducts},
	},
}}

resolved_slsav1_task(name, resolved_params, resolved_results) := {
	"name": name,
	"params": resolved_params,
	"results": resolved_results,
	"taskRef": {
		"params": [
			{
				"name": "name",
				"value": name,
			},
			{
				"name": "bundle",
				"value": concat("-", [name, "bundle"]),
			},
			{
				"name": "kind",
				"value": "task",
			},
		],
		"resolver": "bundles",
	},
	"workspaces": [{
		"name": name,
		"workspace": concat("-", [name, "workspace"]),
	}],
}

# create a task and add a bundle to it
slsav1_task_bundle(name, bundle) := task if {
	not name.taskRef
	base_task := slsav1_task(name)

	# Find the index of the bundle parameter in taskRef.params array
	bundle_idx := [i | some i, p in base_task.taskRef.params; p.name == "bundle"][0]
	task := json.patch(base_task, [{
		"op": "replace",
		"path": sprintf("/taskRef/params/%d/value", [bundle_idx]),
		"value": bundle,
	}])
}

# add a bundle to an existing task
slsav1_task_bundle(name, bundle) := task if {
	name.taskRef
	base_task := name

	# Find the index of the bundle parameter in taskRef.params array
	bundle_idx := [i | some i, p in base_task.taskRef.params; p.name == "bundle"][0]
	task := json.patch(base_task, [{
		"op": "replace",
		"path": sprintf("/taskRef/params/%d/value", [bundle_idx]),
		"value": bundle,
	}])
}

# results are an array of dictionaries with keys, "name", "type", "value"
slsav1_task_result(name, results) := resolved_slsav1_task(name, [], results)

# results are an array of dictionaries with keys, "name", "type", "value"
slsav1_task_result_ref(name, results) := resolved_slsav1_task(name, [], _marshal_slsav1_results(results))

_marshal_slsav1_results(results) := [r |
	some result in results
	r := {"name": result.name, "type": result.type, "value": json.marshal(result.value)}
]

resolved_dependencies(tasks) := [r |
	some task in tasks
	r := {
		"name": "pipelineTask",
		"content": base64.encode(json.marshal(task)),
	}
]
