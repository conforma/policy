package lib.tekton_test

import rego.v1

import data.lib.assertions
import data.lib.tekton

_image := "registry.img/test@sha256:digest"

_image_key := "oci://registry.img/test"

_image_digest := "sha256:digest"

_unpinned_image := "registry.img/test:latest"

_unpinned_image_key := "oci://registry.img/test:latest"

_git_path := "tasks/test.yaml"

_git_commit := "48df630394794f28142224295851a45eea5c63ae"

_git_branch := "main"

_git_url := "https://git.local/repo"

_git_key := "git+https://git.local/repo.git//tasks/test.yaml"

test_bundle_in_definition if {
	assertions.assert_equal(
		tekton.task_ref({"taskRef": {"bundle": _image, "name": "test", "kind": "Task"}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": "test", "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)

	assertions.assert_equal(
		tekton.task_ref({"taskRef": {"bundle": _unpinned_image, "name": "test", "kind": "Task"}}),
		# regal ignore:line-length
		{"bundle": _unpinned_image, "kind": "task", "name": "test", "pinned": false, "tagged": true, "tagged_ref": "latest", "key": _unpinned_image_key},
	)
}

test_bundle_in_slsa_v1_0 if {
	assertions.assert_equal(
		tekton.task_ref({"spec": {"taskRef": {"name": "test", "kind": "Task", "bundle": _image}}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": "test", "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)

	assertions.assert_equal(
		tekton.task_ref({"spec": {"taskRef": {"name": "test", "kind": "Task", "bundle": _unpinned_image}}}),
		# regal ignore:line-length
		{"bundle": _unpinned_image, "kind": "task", "name": "test", "pinned": false, "tagged": true, "tagged_ref": "latest", "key": _unpinned_image_key},
	)
}

test_bundle_in_slsa_v0_2 if {
	assertions.assert_equal(
		tekton.task_ref({"ref": {"name": "test", "kind": "Task", "bundle": _image}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": "test", "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)

	assertions.assert_equal(
		tekton.task_ref({"ref": {"name": "test", "kind": "Task", "bundle": _unpinned_image}}),
		# regal ignore:line-length
		{"bundle": _unpinned_image, "kind": "task", "name": "test", "pinned": false, "tagged": true, "tagged_ref": "latest", "key": _unpinned_image_key},
	)
}

test_bundles_resolver_in_definition if {
	assertions.assert_equal(
		tekton.task_ref({"taskRef": {"resolver": "bundles", "params": [
			{"name": "bundle", "value": _image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		]}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": "test", "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)

	assertions.assert_equal(
		tekton.task_ref({"taskRef": {"resolver": "bundles", "params": [
			{"name": "bundle", "value": _unpinned_image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		]}}),
		# regal ignore:line-length
		{"bundle": _unpinned_image, "kind": "task", "name": "test", "pinned": false, "tagged": true, "tagged_ref": "latest", "key": _unpinned_image_key},
	)
}

test_bundles_resolver_in_slsa_v1_0 if {
	assertions.assert_equal(
		tekton.task_ref({"spec": {"taskRef": {"resolver": "bundles", "params": [
			{"name": "bundle", "value": _image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		]}}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": "test", "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)

	assertions.assert_equal(
		tekton.task_ref({"spec": {"taskRef": {"resolver": "bundles", "params": [
			{"name": "bundle", "value": _unpinned_image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		]}}}),
		# regal ignore:line-length
		{"bundle": _unpinned_image, "kind": "task", "name": "test", "pinned": false, "tagged": true, "tagged_ref": "latest", "key": _unpinned_image_key},
	)
}

test_bundles_resolver_in_slsa_v0_2 if {
	assertions.assert_equal(
		tekton.task_ref({"ref": {"resolver": "bundles", "params": [
			{"name": "bundle", "value": _image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		]}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": "test", "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)

	assertions.assert_equal(
		tekton.task_ref({"ref": {"resolver": "bundles", "params": [
			{"name": "bundle", "value": _unpinned_image},
			{"name": "name", "value": "test"},
			{"name": "kind", "value": "task"},
		]}}),
		# regal ignore:line-length
		{"bundle": _unpinned_image, "kind": "task", "name": "test", "pinned": false, "tagged": true, "tagged_ref": "latest", "key": _unpinned_image_key},
	)
}

test_git_resolver_in_definition if {
	# NOTE: When using the git resolver, the name of the Task is only known when the Task/Pipeline
	# is executed. Since we are testing a resource definition here, the Task reference name in
	# always unknown.

	assertions.assert_equal(
		tekton.task_ref({"taskRef": {"resolver": "git", "params": [
			{"name": "revision", "value": _git_commit},
			{"name": "pathInRepo", "value": _git_path},
			{"name": "url", "value": _git_url},
		]}}),
		{
			"kind": "task",
			"name": tekton._no_task_name,
			"pathInRepo": _git_path,
			"revision": _git_commit,
			"url": _git_url,
			"pinned": true,
			"pinned_ref": _git_commit,
			"key": _git_key,
		},
	)

	assertions.assert_equal(
		tekton.task_ref({"taskRef": {"resolver": "git", "params": [
			{"name": "revision", "value": _git_branch},
			{"name": "pathInRepo", "value": _git_path},
			{"name": "url", "value": _git_url},
		]}}),
		{
			"kind": "task",
			"name": tekton._no_task_name,
			"pathInRepo": _git_path,
			"revision": _git_branch,
			"url": _git_url,
			"pinned": false,
			"key": _git_key,
		},
	)
}

test_git_resolver_in_slsa_v1_0 if {
	assertions.assert_equal(
		tekton.task_ref({
			"metadata": {"labels": {"tekton.dev/task": "test"}},
			"spec": {"taskRef": {"resolver": "git", "params": [
				{"name": "revision", "value": _git_commit},
				{"name": "pathInRepo", "value": _git_path},
				{"name": "url", "value": _git_url},
			]}},
		}),
		{
			"kind": "task",
			"name": "test",
			"pathInRepo": _git_path,
			"revision": _git_commit,
			"url": _git_url,
			"pinned": true,
			"pinned_ref": _git_commit,
			"key": _git_key,
		},
	)

	assertions.assert_equal(
		tekton.task_ref({
			"metadata": {"labels": {"tekton.dev/task": "test"}},
			"spec": {"taskRef": {"resolver": "git", "params": [
				{"name": "revision", "value": _git_branch},
				{"name": "pathInRepo", "value": _git_path},
				{"name": "url", "value": _git_url},
			]}},
		}),
		{
			"kind": "task",
			"name": "test",
			"pathInRepo": _git_path,
			"revision": _git_branch,
			"url": _git_url,
			"pinned": false,
			"key": _git_key,
		},
	)
}

test_git_resolver_in_slsa_v0_2 if {
	assertions.assert_equal(
		tekton.task_ref({
			"invocation": {"environment": {"labels": {"tekton.dev/task": "test"}}},
			"ref": {"resolver": "git", "params": [
				{"name": "revision", "value": _git_commit},
				{"name": "pathInRepo", "value": _git_path},
				{"name": "url", "value": _git_url},
			]},
		}),
		{
			"kind": "task",
			"name": "test",
			"pathInRepo": _git_path,
			"revision": _git_commit,
			"url": _git_url,
			"pinned": true,
			"pinned_ref": _git_commit,
			"key": _git_key,
		},
	)

	assertions.assert_equal(
		tekton.task_ref({
			"invocation": {"environment": {"labels": {"tekton.dev/task": "test"}}},
			"ref": {"resolver": "git", "params": [
				{"name": "revision", "value": _git_branch},
				{"name": "pathInRepo", "value": _git_path},
				{"name": "url", "value": _git_url},
			]},
		}),
		{
			"kind": "task",
			"name": "test",
			"pathInRepo": _git_path,
			"revision": _git_branch,
			"url": _git_url,
			"pinned": false,
			"key": _git_key,
		},
	)
}

test_git_resolver_canonical_key if {
	task := {"ref": {"resolver": "git", "params": [
		{"name": "url", "value": null},
		{"name": "pathInRepo", "value": "pa/th"},
	]}}

	expected := "git+git.local/repo.git//pa/th"

	assertions.assert_equal(
		tekton.task_ref(json.patch(task, [{"op": "add", "path": "/ref/params/0/value", "value": "git.local/repo"}])).key,
		expected,
	)

	assertions.assert_equal(
		tekton.task_ref(json.patch(task, [{"op": "add", "path": "/ref/params/0/value", "value": "git.local/repo.git"}])).key,
		expected,
	)

	assertions.assert_equal(
		tekton.task_ref(json.patch(task, [{"op": "add", "path": "/ref/params/0/value", "value": "git+git.local/repo"}])).key,
		expected,
	)

	assertions.assert_equal(
		# regal ignore:line-length
		tekton.task_ref(json.patch(task, [{"op": "add", "path": "/ref/params/0/value", "value": "git+git.local/repo.git"}])).key,
		expected,
	)
}

test_inlined_task_in_definition if {
	assertions.assert_equal(
		tekton.task_ref({"taskSpec": {"params": [], "steps": []}}),
		{"kind": "task", "name": tekton._no_task_name, "pinned": true, "pinned_ref": "<INLINED>", "key": "<UNKNOWN>"},
	)
}

test_inlined_task_in_slsa_v1_0 if {
	assertions.assert_equal(
		tekton.task_ref({"spec": {"taskSpec": {"steps": [], "params": []}}}),
		{"kind": "task", "name": tekton._no_task_name, "pinned": true, "pinned_ref": "<INLINED>", "key": "<UNKNOWN>"},
	)
}

test_inlined_task_in_slsa_v0_2 if {
	assertions.assert_equal(
		tekton.task_ref({"ref": {}}),
		{"kind": "task", "name": tekton._no_task_name, "pinned": true, "pinned_ref": "<INLINED>", "key": "<UNKNOWN>"},
	)
}

test_local_task_in_definition if {
	assertions.assert_equal(
		tekton.task_ref({"taskRef": {"name": "test", "kind": "Task"}}),
		{"kind": "task", "name": "test", "pinned": false, "key": "<UNKNOWN>"},
	)
}

test_local_task_in_slsa_v1_0 if {
	assertions.assert_equal(
		tekton.task_ref({"spec": {"taskRef": {"name": "test", "kind": "Task"}}}),
		{"kind": "task", "name": "test", "pinned": false, "key": "<UNKNOWN>"},
	)
}

test_local_task_in_slsa_v0_2 if {
	assertions.assert_equal(
		tekton.task_ref({"ref": {"name": "test", "kind": "Task"}}),
		{"kind": "task", "name": "test", "pinned": false, "key": "<UNKNOWN>"},
	)
}

test_bundle_with_defaults if {
	assertions.assert_equal(
		tekton.task_ref({"ref": {"bundle": _image}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": tekton._no_task_name, "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)
}

test_bundle_resolver_with_defaults if {
	assertions.assert_equal(
		tekton.task_ref({"ref": {"resolver": "bundles", "params": [{"name": "bundle", "value": _image}]}}),
		# regal ignore:line-length
		{"bundle": _image, "kind": "task", "name": tekton._no_task_name, "pinned": true, "pinned_ref": _image_digest, "tagged": false, "key": _image_key},
	)
}
