package pre_build_script_task_test

import rego.v1

import data.lib
import data.pre_build_script_task

test_good_pre_build_script_tasks if {
	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [_good_attestation, _cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}

	good_attestation_with_image_index := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/2",
		"value": {
			"name": "run-script-oci-ta-3",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"SCRIPT": "/some-other-script.sh",
				"SCRIPT_RUNNER_IMAGE": "quay.io/konflux-ci/bazel6-ubi9@sha256:not-in-sbom",
			}},
			"results": [{"name": "SCRIPT_RUNNER_IMAGE_REFERENCE", "value": "quay.io/konflux-ci/bazel6-ubi9@sha256:not-in-sbom"}],
		},
	}])

	image_manifest := {"mediaType": "application/vnd.oci.image.index.v1+json"}

	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [good_attestation_with_image_index, _cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with ec.oci.descriptor as image_manifest
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
}

test_disallowed_script_task_runner_image if {
	expected := {{
		"code": "pre_build_script_task.pre_build_script_task_runner_image_allowed",
		"msg": "Pre-Build-Script task runner image \"malicious.io/img:latest@sha256:abc\" is from a disallowed registry",
		"term": "malicious.io/img",
	}}

	disallowed_image := json.patch(_good_attestation, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/0/invocation/parameters/SCRIPT_RUNNER_IMAGE",
		"value": "malicious.io/img:latest@sha256:abc",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [disallowed_image, _cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
}

test_pre_build_image_not_in_task_result if {
	expected := {{
		"code": "pre_build_script_task.pre_build_script_task_runner_image_in_results",
		"msg": "The runner image used for the pre-Build-Script task 'run-script-oci-ta' is not listed in the task results",
	}}

	attestation_missing_task_result := json.patch(_good_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/buildConfig/tasks/0/results/0",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [attestation_missing_task_result, _cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
}

test_pre_build_image_in_sbom if {
	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [_good_attestation, _cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}

	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [_good_attestation, _spdx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
}

test_pre_build_image_in_sbom_ignoring_tag if {
	# Add a tag into the image refs as well as the digest, "some-tag" and "latest".
	good_attestation_with_tag_in_image_ref := json.patch(_good_attestation, [
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/0/results/0/value",
			"value": "registry.redhat.io/ubi7:some-tag@sha256:bcd",
		},
		{
			"op": "replace",
			"path": "/statement/predicate/buildConfig/tasks/1/results/0/value",
			"value": "quay.io/konflux-ci/bazel6-ubi9:latest@sha256:def",
		},
	])

	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [good_attestation_with_tag_in_image_ref, _cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}

	# regal ignore:line-length
	lib.assert_empty(pre_build_script_task.deny) with input.attestations as [good_attestation_with_tag_in_image_ref, _spdx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
}

test_pre_build_image_not_in_sbom if {
	expected := {{
		"code": "pre_build_script_task.pre_build_script_task_runner_image_in_sbom",
		"msg": "Pre-Build-Script task runner image \"registry.redhat.io/ubi7@sha256:bcd\" is not in the SBOM",
	}}

	incomplete_cyclonedx_sbom_attestation := json.patch(_cyclonedx_sbom_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/components/1",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [_good_attestation, incomplete_cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}

	incomplete_spdx_sbom_attestation := json.patch(_spdx_sbom_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/packages/0/externalRefs/1",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [_good_attestation, incomplete_spdx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
}

test_pre_build_image_reference_is_not_valid if {
	expected := {{
		"code": "pre_build_script_task.valid_pre_build_script_task_runner_image_ref",
		# regal ignore:line-length
		"msg": "Pre-Build-Script task runner image \"not-a-valid-image-ref\" is not a valid image reference",
	}}

	invalid_prebuild_img_attestation := json.patch(_good_attestation, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/0/results/0/value",
		"value": "not-a-valid-image-ref",
	}])

	# regal ignore:line-length
	lib.assert_equal_results(expected, pre_build_script_task.deny) with input.attestations as [invalid_prebuild_img_attestation, _cyclonedx_sbom_attestation]
		with data.rule_data.allowed_step_image_registry_prefixes as _allowed_registries
		with input.image as {"ref": "registry.io/repository/image@sha256:284e3029"}
}

_good_attestation := {"statement": {"predicate": {
	"buildType": lib.tekton_pipeline_run,
	"buildConfig": {"tasks": [
		{
			"name": "run-script-oci-ta-1",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"SCRIPT": "/some-script.sh",
				"SCRIPT_RUNNER_IMAGE": "registry.redhat.io/ubi7@sha256:bcd",
			}},
			"results": [{"name": "SCRIPT_RUNNER_IMAGE_REFERENCE", "value": "registry.redhat.io/ubi7@sha256:bcd"}],
		},
		{
			"name": "run-script-oci-ta-2",
			"ref": {"kind": "Task", "name": "run-script-oci-ta", "bundle": "reg.img/spam@sha256:abc"},
			"invocation": {"parameters": {
				"SCRIPT": "/some-other-script.sh",
				"SCRIPT_RUNNER_IMAGE": "quay.io/konflux-ci/bazel6-ubi9@sha256:def",
			}},
			"results": [{"name": "SCRIPT_RUNNER_IMAGE_REFERENCE", "value": "quay.io/konflux-ci/bazel6-ubi9@sha256:def"}],
		},
	]},
}}}

_allowed_registries := ["registry.redhat.io/", "quay.io/konflux-ci/bazel6-ubi9"]

_spdx_sbom_attestation := {"statement": {
	"predicateType": "https://spdx.dev/Document",
	"predicate": {"packages": [{"externalRefs": [
		{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			"referenceLocator": "pkg:oci/spam@sha256:abc?repository_url=example.com/org/spam",
		},
		{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			"referenceLocator": "pkg:oci/ubi7@sha256:bcd?repository_url=registry.redhat.io/ubi7",
		},
		{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			"referenceLocator": "pkg:oci/bazel6-ubi9@sha256:def?repository_url=quay.io/konflux-ci/bazel6-ubi9",
		},
	]}]},
}}

_cyclonedx_sbom_attestation := {"statement": {
	"predicateType": "https://cyclonedx.org/bom",
	"predicate": {"components": [
		{"purl": "pkg:oci/spam@sha256:abc?repository_url=example.com/org/spam"},
		{"purl": "pkg:oci/ubi7@sha256:bcd?repository_url=registry.redhat.io/ubi7"},
		{"purl": "pkg:oci/bazel6-ubi9@sha256:def?repository_url=quay.io/konflux-ci/bazel6-ubi9"},
	]},
}}
