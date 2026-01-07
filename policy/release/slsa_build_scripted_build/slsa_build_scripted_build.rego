#
# METADATA
# title: SLSA - Build - Scripted Build
# description: >-
#   The SLSA requirement states the following:
#
#   "All build steps were fully defined in some sort of “build script”.
#   The only manual command, if any, was to invoke the build script."
#
#   This package verifies the requirement by asserting the image was
#   built by Tekton Pipelines.
#
package slsa_build_scripted_build

import rego.v1

import data.lib
import data.lib.image
import data.lib.tekton

# Batch fetch all manifests for tasks in the pipelineRun attestation
_manifests := ec.oci.image_manifests(lib.pipelinerun_bundle_refs)

# METADATA
# title: Build task contains steps
# description: >-
#   Verify that the predicate.buildConfig.tasks.steps attribute for the task
#   responsible for building and pushing the image is not empty.
# custom:
#   short_name: build_script_used
#   failure_msg: Build task %q does not contain any steps
#   solution: >-
#     There were no build tasks detected. Make sure the build pipeline contains
#     tasks and that the build system is recording them properly when the attestation
#     is generated.
#   collections:
#   - slsa3
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	build_tasks := tekton.build_tasks(attestation)
	some build_task in build_tasks
	count(task_steps(build_task)) == 0
	result := lib.result_helper(rego.metadata.chain(), [build_task.name])
}

# METADATA
# title: Build task set image digest and url task results
# description: >-
#   Confirm that a build task exists and it has the expected
#   IMAGE_DIGEST and IMAGE_URL task results.
# custom:
#   short_name: build_task_image_results_found
#   failure_msg: Build task not found
#   solution: >-
#     Make sure the build pipeline contains a build task. The build task
#     must contain results named 'IMAGE_DIGEST' and 'IMAGE_URL'.
#   collections:
#   - slsa3
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	builds := tekton.build_tasks(attestation)
	count(builds) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Provenance subject matches build task image result
# description: >-
#   Verify the subject of the attestations matches the IMAGE_DIGEST and
#   IMAGE_URL values from the build task.
# custom:
#   short_name: subject_build_task_matches
#   failure_msg: The attestation subject, %q, does not match any of the images built
#   solution: >-
#     Make sure the subject in the attestation matches the 'IMAGE_URL' and 'IMAGE_DIGEST'
#     results from the build task. The format for the subject should be 'IMAGE_URL@IMAGE_DIGEST'.
#   collections:
#   - slsa3
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	subject_image_refs := collect_subjects(attestation)

	build_tasks := tekton.build_tasks(attestation)

	count(build_tasks) > 0

	# all image results within all build tasks
	result_image_refs := tekton.images_with_digests(build_tasks)
	some subject_image_ref in subject_image_refs
	not _contains_equal_ref(result_image_refs, subject_image_ref)

	result := lib.result_helper(rego.metadata.chain(), [subject_image_ref])
}

# METADATA
# title: Image built by trusted Task
# description: >-
#   Verify the digest of the image being validated is reported by a trusted Task in its IMAGE_DIGEST
#   result.
# custom:
#   short_name: image_built_by_trusted_task
#   failure_msg: 'Image %q not built by a trusted task: %s'
#   solution: Make sure the build Pipeline definition uses a trusted Task to build images.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	expected_ref := input.image.ref
	expected_digest := image.parse(expected_ref).digest

	# Find all the Tekton Bundle references from the Tasks that claim to have built the image being
	# validated.
	tasks := {build_task |
		some attestation in lib.pipelinerun_attestations
		some build_task in tekton.build_tasks(attestation)
		digests := tekton.task_result_artifact_digest(build_task)
		_contains_digest(digests, expected_digest)
	}

	error := _trusted_build_task_error(tasks)
	result := lib.result_helper(rego.metadata.chain(), [expected_ref, error])
}

task_steps(task) := steps if {
	steps := task.steps
} else := []

subject_digest(subject) := digest if {
	some algorithm, value in subject.digest
	digest := concat(":", [algorithm, value])
}

collect_subjects(attestation) := [subject_image_ref |
	some subject in attestation.statement.subject
	subject_image_ref := concat("@", [subject.name, subject_digest(subject)])
]

_trusted_build_task_error(tasks) := error if {
	count(tasks) == 0
	error := "No Pipeline Tasks built the image"
} else := error if {
	untrusted_tasks := tekton.untrusted_task_refs(lib.tasks_from_pipelinerun, _manifests)
	untrusted_build_tasks = untrusted_tasks & tasks
	count(untrusted_build_tasks) > 0

	names := {name |
		some task in untrusted_build_tasks
		name := tekton.task_name(task)
	}
	error := sprintf("Build Task(s) %q are not trusted", [concat(",", names)])
}

_contains_equal_ref(arr, item) := matched if {
	matched := [match |
		some match in arr
		image.equal_ref(match, item)
	]
	count(matched) > 0
}

_contains_digest(arr, item) := matched if {
	matched := [match |
		some match in arr
		match == item
	]
	count(matched) > 0
}
