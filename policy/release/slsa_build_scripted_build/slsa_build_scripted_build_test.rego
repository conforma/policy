package slsa_build_scripted_build_test

import rego.v1

import data.lib
import data.slsa_build_scripted_build

mock_bundle_digest := "sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

mock_bundle_repo := "registry.img/spam:v1"

mock_bundle := sprintf("%s@%s", [mock_bundle_repo, mock_bundle_digest])

test_all_good if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	image := {"ref": _image_ref}

	group := sprintf("oci://%s", [mock_bundle_repo])
	trusted_tasks := {group: [{"ref": mock_bundle_digest, "effective_on": "2023-11-06T00:00:00Z"}]}

	lib.assert_empty(slsa_build_scripted_build.deny) with input.image as image
		with input.attestations as [_mock_attestation(tasks)]
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
}

# It's unclear if this should be allowed or not. This unit test exists to
# highlight the current behavior.
test_scattered_results if {
	tasks := [
		{
			"results": [{"name": "IMAGE_URL", "value": _image_url}],
			"ref": {"bundle": mock_bundle},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
		{
			"results": [{"name": "IMAGE_DIGEST", "value": _image_digest}],
			"ref": {"bundle": mock_bundle},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
	]

	expected := {{
		"code": "slsa_build_scripted_build.build_task_image_results_found",
		"msg": "Build task not found",
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_missing_task_steps if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {"bundle": mock_bundle},
		# "steps" is not defined
	}]

	expected := {{
		"code": "slsa_build_scripted_build.build_script_used",
		"msg": "Build task \"buildah\" does not contain any steps",
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_empty_task_steps if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [],
	}]

	expected := {{
		"code": "slsa_build_scripted_build.build_script_used",
		"msg": "Build task \"buildah\" does not contain any steps",
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_build_script_used_many_build_tasks if {
	tasks := [
		{
			"name": "build-1",
			"results": [
				{"name": "IMAGE_URL", "value": _image_url},
				{"name": "IMAGE_DIGEST", "value": _image_digest},
			],
			"ref": {"bundle": mock_bundle},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
		{
			"name": "build-2",
			"results": [
				{"name": "IMAGE_URL", "value": _image_url},
				{"name": "IMAGE_DIGEST", "value": _image_digest},
			],
			"ref": {"bundle": mock_bundle},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
	]

	# all good
	lib.assert_empty(slsa_build_scripted_build.deny) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests

	# one of the build tasks doesn't have any steps
	expected_scripted := {{
		"code": "slsa_build_scripted_build.build_script_used",
		"msg": "Build task \"build-2\" does not contain any steps",
	}}
	lib.assert_equal_results(
		expected_scripted,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(json.patch(tasks, [{
		"op": "remove",
		"path": "1/steps",
	}]))]
		with ec.oci.image_manifests as _mock_image_manifests

	# one of the build tasks produces the expected results, the other one doesn't, this is ok
	lib.assert_empty(slsa_build_scripted_build.deny) with input.attestations as [_mock_attestation(json.patch(tasks, [{
		"op": "replace",
		"path": "1/results/0/value",
		"value": "something-else",
	}]))]
		with ec.oci.image_manifests as _mock_image_manifests

	# none of the build tasks produced the expected results
	expected_results := {{
		"code": "slsa_build_scripted_build.subject_build_task_matches",
		"msg": `The attestation subject, "some.image/foo:bar@sha256:123", does not match any of the images built`,
	}}
	lib.assert_equal_results(
		expected_results,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(json.patch(tasks, [
		{
			"op": "replace",
			"path": "0/results/0/value",
			"value": "something-else",
		},
		{
			"op": "replace",
			"path": "1/results/0/value",
			"value": "something-else",
		},
	]))]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_results_missing_value_url if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL"},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [],
	}]

	expected := {{
		"code": "slsa_build_scripted_build.build_task_image_results_found",
		"msg": "Build task not found",
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_results_missing_value_digest if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "url"},
			{"name": "IMAGE_DIGEST"},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [],
	}]

	expected := {{
		"code": "slsa_build_scripted_build.build_task_image_results_found",
		"msg": "Build task not found",
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_results_empty_value_url if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": ""},
			{"name": "IMAGE_DIGEST", "value": "digest"},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [],
	}]

	expected := {{
		"code": "slsa_build_scripted_build.build_task_image_results_found",
		"msg": "Build task not found",
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_results_empty_value_digest if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "url"},
			{"name": "IMAGE_DIGEST", "value": ""},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [],
	}]

	expected := {{
		"code": "slsa_build_scripted_build.build_task_image_results_found",
		"msg": "Build task not found",
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_subject_mismatch if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": "sha256:anotherdigest"},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "slsa_build_scripted_build.subject_build_task_matches",
		"msg": `The attestation subject, "some.image/foo:bar@sha256:123", does not match any of the images built`,
	}}

	lib.assert_equal_results(
		expected,
		slsa_build_scripted_build.deny,
	) with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_subject_with_tag_and_digest_is_good if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry.io/repository/image:tag"},
			{"name": "IMAGE_DIGEST", "value": "sha256:digest"},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	lib.assert_empty(slsa_build_scripted_build.deny) with input.attestations as [{"statement": {
		"subject": [{
			"name": "registry.io/repository/image",
			"digest": {"sha256": "digest"},
		}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": tasks},
		},
	}}]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_subject_with_tag_and_digest_mismatch_tag_is_good if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry.io/repository/image:tag"},
			{"name": "IMAGE_DIGEST", "value": "sha256:digest"},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	lib.assert_empty(slsa_build_scripted_build.deny) with input.attestations as [{"statement": {
		"subject": [{
			"name": "registry.io/repository/image:different",
			"digest": {"sha256": "digest"},
		}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": tasks},
		},
	}}]
}

test_subject_with_tag_and_digest_mismatch_digest_fails if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": "registry.io/repository/image:tag"},
			{"name": "IMAGE_DIGEST", "value": "sha256:digest"},
		],
		"ref": {"bundle": mock_bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "slsa_build_scripted_build.subject_build_task_matches",
		# regal ignore:line-length
		"msg": `The attestation subject, "registry.io/repository/image@sha256:unexpected", does not match any of the images built`,
	}}

	lib.assert_equal_results(expected, slsa_build_scripted_build.deny) with input.attestations as [{"statement": {
		"subject": [{
			"name": "registry.io/repository/image",
			"digest": {"sha256": "unexpected"},
		}],
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": tasks},
		},
	}}]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_image_built_by_trusted_task_no_build_task if {
	att := json.patch(
		_mock_attestation([{
			"results": [
				{"name": "IMAGE_URL", "value": _image_url},
				{"name": "IMAGE_DIGEST", "value": "sha256:abc"},
			],
			"ref": {"bundle": mock_bundle},
			"steps": [{"entrypoint": "/bin/bash"}],
		}]),
		[{
			"op": "add",
			"path": "/statement/subject/0/digest/sha256",
			"value": "abc",
		}],
	)

	image := {"ref": _image_ref}

	expected := {{
		"code": "slsa_build_scripted_build.image_built_by_trusted_task",
		"msg": "Image \"some.image/foo:bar@sha256:123\" not built by a trusted task: No Pipeline Tasks built the image",
	}}

	lib.assert_equal_results(expected, slsa_build_scripted_build.deny) with input.image as image
		with input.attestations as [att]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_image_built_by_trusted_task_not_trusted if {
	tasks := [{
		"results": [
			{"name": "IMAGE_URL", "value": _image_url},
			{"name": "IMAGE_DIGEST", "value": _image_digest},
		],
		"ref": {
			"resolver": "bundles",
			"params": [
				{"name": "bundle", "value": mock_bundle},
				{"name": "name", "value": "buildah"},
				{"name": "kind", "value": "task"},
			],
		},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	image := {"ref": _image_ref}

	expected := {{
		"code": "slsa_build_scripted_build.image_built_by_trusted_task",
		# regal ignore:line-length
		"msg": `Image "some.image/foo:bar@sha256:123" not built by a trusted task: Build Task(s) "buildah" are not trusted`,
	}}

	lib.assert_equal_results(expected, slsa_build_scripted_build.deny) with input.image as image
		with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

test_image_built_by_multiple_not_trusted_tasks if {
	tasks := [
		{
			"results": [
				{"name": "IMAGE_URL", "value": _image_url},
				{"name": "IMAGE_DIGEST", "value": _image_digest},
			],
			"ref": {
				"resolver": "bundles",
				"params": [
					{"name": "bundle", "value": mock_bundle},
					{"name": "name", "value": "buildah-1"},
					{"name": "kind", "value": "task"},
				],
			},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
		{
			"results": [
				{"name": "IMAGE_URL", "value": _image_url},
				{"name": "IMAGE_DIGEST", "value": _image_digest},
			],
			"ref": {
				"resolver": "bundles",
				"params": [
					{"name": "bundle", "value": mock_bundle},
					{"name": "name", "value": "buildah-2"},
					{"name": "kind", "value": "task"},
				],
			},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
	]

	image := {"ref": _image_ref}

	expected := {{
		"code": "slsa_build_scripted_build.image_built_by_trusted_task",
		# regal ignore:line-length
		"msg": `Image "some.image/foo:bar@sha256:123" not built by a trusted task: Build Task(s) "buildah-1,buildah-2" are not trusted`,
	}}

	lib.assert_equal_results(expected, slsa_build_scripted_build.deny) with input.image as image
		with input.attestations as [_mock_attestation(tasks)]
		with ec.oci.image_manifests as _mock_image_manifests
}

_image_url := "some.image/foo:bar"

_image_digest_algorithm := "sha256"

_image_digest_value := "123"

_image_digest := concat(":", [_image_digest_algorithm, _image_digest_value])

_image_ref := sprintf("%s@%s", [_image_url, _image_digest])

_mock_attestation(original_tasks) := d if {
	default_task := {
		"name": "buildah",
		"ref": {"kind": "Task"},
	}

	tasks := [task |
		some original_task in original_tasks
		task := object.union(default_task, original_task)
	]

	d := {"statement": {
		"subject": generate_subjects(original_tasks),
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": tasks},
		},
	}}
}

generate_subjects(tasks) := [subject |
	some task in tasks
	subject := {
		"name": _image_url,
		"digest": {_image_digest_algorithm: _image_digest_value},
	}
]

# Mock function for ec.oci.image_manifests
# Returns a map of bundle_ref -> manifest for test bundles
_mock_image_manifests(refs) := {ref: manifest |
	some ref in refs
	manifest := {}
}
