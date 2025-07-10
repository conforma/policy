#
# METADATA
# title: Trusted Task checks
# description: >-
#   This package is used to verify all the Tekton Tasks involved in building the image are trusted.
#   Trust is established by comparing the Task references found in the SLSA Provenance with a
#   pre-defined list of trusted Tasks, which is expected to be provided as a data source that
#   creates the `data.trusted_tasks` in the format demonstrated at
#   https://github.com/conforma/policy/blob/main/example/data/trusted_tekton_tasks.yml.
#   The list can be extended or customized using the `trusted_tasks` rule data key which is merged
#   into the `trusted_tasks` data.
#
package trusted_task

import rego.v1

import data.lib
import data.lib.image
import data.lib.tekton

_supported_ta_uris_reg := {"oci:.*@sha256:[0-9a-f]{64}"}

_digest_patterns := {`sha256:[0-9a-f]{64}`}

# METADATA
# title: Task references are tagged
# description: >-
#   Check if all Tekton Tasks defined with the bundle format contain a tag reference.
# custom:
#   short_name: tagged
#   failure_msg: Pipeline task %q uses an untagged task reference, %s
#   solution: >-
#     Update the Pipeline definition so that all Task references have a tagged value as mentioned
#     in the description.
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: 2024-05-07T00:00:00Z
#
warn contains result if {
	some task in tekton.untagged_task_references(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tekton.pipeline_task_name(task), _task_info(task)],
		tekton.task_name(task),
	)
}

# METADATA
# title: Task references are pinned
# description: >-
#   Check if all Tekton Tasks use a Task definition by a pinned reference. When using the git
#   resolver, a commit ID is expected for the revision parameter. When using the bundles resolver,
#   the bundle parameter is expected to include an image reference with a digest.
# custom:
#   short_name: pinned
#   failure_msg: Pipeline task %q uses an unpinned task reference, %s
#   solution: >-
#     Update the Pipeline definition so that all Task references have a pinned value as mentioned
#     in the description.
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: 2024-05-07T00:00:00Z
#
warn contains result if {
	some task in tekton.unpinned_task_references(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tekton.pipeline_task_name(task), _task_info(task)],
		tekton.task_name(task),
	)
}

# METADATA
# title: Tasks using the latest versions
# description: >-
#   Check if all Tekton Tasks use the latest known Task reference. When warnings
#   will be reported can be configured using the `task_expiry_warning_days` rule
#   data setting. It holds the number of days before the task is to expire within
#   which the warnings will be reported.
# custom:
#   short_name: current
#   failure_msg: >-
#     A newer version of task %q exists. Please update before %s.
#     The current bundle is %q and the latest bundle ref is %q
#   solution: >-
#     Update the Task reference to a newer version.
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: 2024-05-07T00:00:00Z
#
warn contains result if {
	some task in lib.tasks_from_pipelinerun
	expiry := tekton.expiry_of(task)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tekton.pipeline_task_name(task), time.format(expiry), _task_info(task), tekton.latest_trusted_ref(task)],
		tekton.task_name(task),
	)
}

# METADATA
# title: Tasks are trusted
# description: >-
#   Check the trust of the Tekton Tasks used in the build Pipeline. There are two modes in which
#   trust is verified. The first mode is used if Trusted Artifacts are enabled. In this case, a
#   chain of trust is established for all the Tasks involved in creating an artifact. If the chain
#   contains an untrusted Task, then a violation is emitted. The second mode is used as a fallback
#   when Trusted Artifacts are not enabled. In this case, **all** Tasks in the build Pipeline must
#   be trusted.
# custom:
#   short_name: trusted
#   failure_msg: "%s"
#   solution: >-
#     If using Trusted Artifacts, be sure every Task in the build Pipeline responsible for producing
#     a Trusted Artifact is trusted. Otherwise, ensure **all** Tasks in the build Pipeline are
#     trusted. Note that trust is eventually revoked from Tasks when newer versions are made
#     available.
#   collections:
#   - redhat
#   effective_on: 2024-05-07T00:00:00Z
#
deny contains result if {
	some err in _trust_errors
	result := lib.result_helper_with_term(rego.metadata.chain(), [err.msg], err.term)
}

# METADATA
# title: Trusted Artifact produced in pipeline
# description: >-
#   All input trusted artifacts must be produced on the pipeline. If they are not
#   the artifact could have been injected by a rogue task.
# custom:
#   short_name: valid_trusted_artifact_inputs
#   failure_msg: >-
#     Code tampering detected, input %q for task %q was not produced by the
#     pipeline as attested.
#   solution: >-
#     Audit the pipeline to make sure all inputs are produced by the pipeline.
#   collections:
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.tasks(attestation)
	some invalid_input in _trusted_artifact_inputs(task)
	count({o |
		some t in tekton.tasks(attestation)
		some o in _trusted_artifact_outputs(t)

		o == invalid_input
	}) == 0

	task_name = tekton.pipeline_task_name(task)

	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[invalid_input, task_name],
		invalid_input,
	)
}

# METADATA
# title: Task tracking data was provided
# description: >-
#   Confirm the `trusted_tasks` rule data was provided, since it's required by the policy rules in
#   this package.
# custom:
#   short_name: data
#   failure_msg: Missing required trusted_tasks data
#   solution: >-
#     Create a, or use an existing, trusted tasks list as a data source.
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: 2024-05-07T00:00:00Z
#
deny contains result if {
	tekton.missing_trusted_tasks_data
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Trusted parameters
# description: >-
#   Confirm certain parameters provided to each builder Task have come from trusted Tasks.
# custom:
#   short_name: trusted_parameters
#   failure_msg: 'The %q parameter of the %q PipelineTask includes an untrusted digest: %s'
#   solution: >-
#     Update your build Pipeline to ensure all the parameters provided to your builder Tasks come
#     from trusted Tasks.
#   collections:
#   - redhat
#   effective_on: 2021-07-04T00:00:00Z
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some build_task in tekton.build_tasks(attestation)

	some param_name, param_value in tekton.task_params(build_task)

	# Trusted Artifacts are handled differently. Here we are concerned with all other parameters.
	not endswith(param_name, "_ARTIFACT")
	params_digests := _digests_from_values(lib.param_values(param_value))

	some untrusted_digest in (params_digests - _trusted_build_digests)
	result := lib.result_helper(
		rego.metadata.chain(),
		[param_name, tekton.pipeline_task_name(build_task), untrusted_digest],
	)
}

# METADATA
# title: Data format
# description: >-
#   Confirm the expected `trusted_tasks` data keys have been provided in the expected format.
# custom:
#   short_name: data_format
#   failure_msg: '%s'
#   solution: If provided, ensure the data is in the expected format.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some error in tekton.data_errors
	result := lib.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
}

_trust_errors contains error if {
	_uses_trusted_artifacts
	some attestation in lib.pipelinerun_attestations
	build_tasks := tekton.build_tasks(attestation)
	test_tasks := tekton.tasks_output_result(attestation)
	some build_or_test_task in array.concat(build_tasks, test_tasks)

	dependency_chain := graph.reachable(_artifact_chain[attestation], {tekton.pipeline_task_name(build_or_test_task)})

	chain := [task |
		some link in dependency_chain
		some task in tekton.tasks(attestation)

		link == tekton.pipeline_task_name(task)
	]

	some untrusted_task in tekton.untrusted_task_refs(chain)

	error := _format_trust_error_ta(untrusted_task, dependency_chain)
}

_trust_errors contains error if {
	not _uses_trusted_artifacts
	some untrusted_task in tekton.untrusted_task_refs(lib.tasks_from_pipelinerun)
	error := _format_trust_error(untrusted_task)
}

_artifact_chain[attestation][name] := dependencies if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.tasks(attestation)
	name := tekton.pipeline_task_name(task)
	dependencies := {dep |
		some t in tekton.tasks(attestation)
		some i in _trusted_artifact_inputs(task)
		some o in _trusted_artifact_outputs(t)
		i == o
		dep := tekton.pipeline_task_name(t)
	}
}

_trusted_artifact_inputs(task) := {value |
	some key, value in tekton.task_params(task)
	endswith(key, "_ARTIFACT")
	count({b |
		some supported_uri_ta_reg in _supported_ta_uris_reg
		b = regex.match(supported_uri_ta_reg, value)
		b
	}) == 1
}

_trusted_artifact_outputs(task) := {result.value |
	some result in tekton.task_results(task)
	result.type == "string"
	endswith(result.name, "_ARTIFACT")
	count({b |
		some supported_uri_ta_reg in _supported_ta_uris_reg
		b = regex.match(supported_uri_ta_reg, result.value)
		b
	}) == 1
}

_uses_trusted_artifacts if {
	ta_tasks := {task |
		some task in lib.tasks_from_pipelinerun
		total := count(_trusted_artifact_inputs(task)) + count(_trusted_artifact_outputs(task))
		total > 0
	}
	count(ta_tasks) > 0
}

_task_info(task) := info if {
	ref := tekton.task_ref(task)
	info := sprintf("%s@%s", [object.get(ref, "key", ""), object.get(ref, "pinned_ref", "")])
}

# _trusted_build_digest is a set containing any digest found in one of the trusted builder Tasks.
_trusted_build_digests contains digest if {
	some attestation in lib.pipelinerun_attestations
	some build_task in tekton.build_tasks(attestation)
	tekton.is_trusted_task(build_task)
	some result in tekton.task_results(build_task)
	some digest in _digests_from_values(lib.result_values(result))
}

# If an image is part of the snapshot we assume that was built in Konflux and
# therefore it is considered trustworthy. IIUC the use case is something to do
# with building an image in one component, and being able to use it while
# building another component in the same application.
_trusted_build_digests contains digest if {
	some component in input.snapshot.components
	digest := image.parse(component.containerImage).digest

	# From policy/lib/image/image_test.rego I think it's always going
	# to be a string but let's be defensive and make sure of it
	is_string(digest)

	# Ensure we don't include empty strings in case
	# component.containerImage doesn't include a digest
	digest != ""
}

# If an image is included in the "SCRIPT_RUNNER_IMAGE_REFERENCE" task result
# produced by a trusted "run-script-oci-ta" task, then we permit it. This
# image ref gets placed in the ADDITIONAL_BASE_IMAGES task param for the build
# task so the build task can include the additional base image in the SBOM.
_trusted_build_digests contains digest if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	tekton.is_trusted_task(task)
	runner_image_result_value := tekton.task_result(task, _pre_build_run_script_runner_image_result)
	some digest in _digests_from_values({runner_image_result_value})
}

_pre_build_run_script_runner_image_result := "SCRIPT_RUNNER_IMAGE_REFERENCE"

_digests_from_values(values) := {digest |
	some value in values
	some pattern in _digest_patterns
	some digest in regex.find_n(pattern, value, -1)
}

_format_trust_error_ta(task, dependency_chain) := error if {
	latest_trusted_ref := tekton.latest_trusted_ref(task)
	untrusted_pipeline_task_name := tekton.pipeline_task_name(task)
	untrusted_task_name := tekton.task_name(task)

	error := {
		"msg": sprintf(
			# regal ignore:line-length
			"Untrusted version of PipelineTask %q (Task %q) was included in build chain comprised of: %s. Please upgrade the task version to: %s",
			[untrusted_pipeline_task_name, untrusted_task_name, concat(", ", dependency_chain), latest_trusted_ref],
		),
		"term": untrusted_task_name,
	}
} else := error if {
	untrusted_pipeline_task_name := tekton.pipeline_task_name(task)
	untrusted_task_name := tekton.task_name(task)

	error := {
		"msg": sprintf(
			"Code tampering detected, untrusted PipelineTask %q (Task %q) was included in build chain comprised of: %s",
			[untrusted_pipeline_task_name, untrusted_task_name, concat(", ", dependency_chain)],
		),
		"term": untrusted_task_name,
	}
}

_format_trust_error(task) := error if {
	latest_trusted_ref := tekton.latest_trusted_ref(task)
	untrusted_pipeline_task_name := tekton.pipeline_task_name(task)
	untrusted_task_name := tekton.task_name(task)
	untrusted_task_info := _task_info(task)

	error := {
		"msg": sprintf(
			# regal ignore:line-length
			"PipelineTask %q uses an untrusted task reference: %s. Please upgrade the task version to: %s",
			[untrusted_pipeline_task_name, untrusted_task_info, latest_trusted_ref],
		),
		"term": untrusted_task_name,
	}
} else := error if {
	untrusted_pipeline_task_name := tekton.pipeline_task_name(task)
	untrusted_task_name := tekton.task_name(task)
	untrusted_task_info := _task_info(task)

	error := {
		"msg": sprintf(
			"PipelineTask %q uses an untrusted task reference: %s",
			[untrusted_pipeline_task_name, untrusted_task_info],
		),
		"term": untrusted_task_name,
	}
}
