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

# Batch fetch all manifests for tasks in the pipelineRun attestation
_manifests := ec.oci.image_manifests(lib.pipelinerun_bundle_refs)

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
	# only run if trusted_task_rules are empty
	# this can either go away when trusted_task_rules are fully implemented or we can take
	# a loook at it when versioning is implemented.
	tekton.missing_trusted_task_rules_data
	some task in lib.tasks_from_pipelinerun
	expiry := tekton.expiry_of(task)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tekton.pipeline_task_name(task), time.format(expiry), _task_info(task), tekton.latest_trusted_ref(task)],
		tekton.task_name(task),
	)
}

# METADATA
# title: Future deny rule will apply
# description: >-
#   Warn when a task matches a deny rule that has an effective_on date in the future. This
#   provides advance notice that a task will become untrusted when the deny rule takes effect.
# custom:
#   short_name: future_deny_rule
#   failure_msg: >-
#     Task %q will be denied by rule pattern %q starting on %s.
#   solution: >-
#     Update the Task to a version that will not match the future deny rule before its
#     effective date.
#   collections:
#   - redhat
#
warn contains result if {
	not tekton.missing_trusted_task_rules_data
	some task in lib.tasks_from_pipelinerun
	some rule in tekton.future_deny_rules_for_task(task, _manifests)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[tekton.pipeline_task_name(task), rule.pattern, rule.effective_on],
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
# title: Trusted parameters
# description: >-
#   Confirm certain parameters provided to each builder Task have come from trusted Tasks.
#   Trust can be defined using pattern-based rules (trusted_task_rules) or an explicit allow
#   list with expiry dates (trusted_tasks).
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
	# Only active when trusted task data is present (either system)
	not tekton.missing_all_trusted_tasks_data

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
	tekton.missing_all_trusted_tasks_data
	result := lib.result_helper(rego.metadata.chain(), [])
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

# #############################################################################
# HELPER FUNCTIONS
# #############################################################################
#
# MIGRATION GUIDE: To remove legacy trusted_tasks support and use only trusted_task_rules:
#
# 1. In this file (trusted_task.rego):
#    - Delete the "LEGACY SYSTEM" section below (marked with BEGIN/END comments)
#    - In _trust_errors, remove the rule that routes to _trust_errors_legacy
#    - Simplify _trust_errors to just call _trust_errors_rules directly
#
# 2. In policy/lib/tekton/trusted.rego:
#    - Remove: is_trusted_task_legacy, untrusted_task_refs_legacy
#    - Remove: trusted_task_records, latest_trusted_ref, expiry_of, _task_expires_on
#    - Remove: _trusted_tasks, _trusted_tasks_data, _unexpired_records
#    - Remove: missing_trusted_tasks_data (or update it)
#    - Simplify: is_trusted_task and untrusted_task_refs to call rules versions directly
#
# #############################################################################

# =============================================================================
# ROUTING LAYER
# Routes trust errors to the appropriate system based on data presence.
# Priority: trusted_task_rules > trusted_tasks
# =============================================================================

_trust_errors contains error if {
	not tekton.missing_trusted_task_rules_data
	some error in _trust_errors_rules
}

_trust_errors contains error if {
	tekton.missing_trusted_task_rules_data
	not tekton.missing_trusted_tasks_data
	some error in _trust_errors_legacy
}

# =============================================================================
# SHARED HELPERS
# These functions are used by both the legacy and rules systems.
# Keep these when removing legacy support.
# =============================================================================

# Builds a dependency graph for Trusted Artifacts - maps each task to the tasks it depends on
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

# Returns the set of Trusted Artifact input URIs for a task
_trusted_artifact_inputs(task) := {value |
	some key, value in tekton.task_params(task)
	endswith(key, "_ARTIFACT")
	count({b |
		some supported_uri_ta_reg in _supported_ta_uris_reg
		b = regex.match(supported_uri_ta_reg, value)
		b
	}) == 1
}

# Returns the set of Trusted Artifact output URIs for a task
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

# Returns true if the pipeline uses Trusted Artifacts
_uses_trusted_artifacts if {
	ta_tasks := {task |
		some task in lib.tasks_from_pipelinerun
		total := count(_trusted_artifact_inputs(task)) + count(_trusted_artifact_outputs(task))
		total > 0
	}
	count(ta_tasks) > 0
}

# Formats a task reference as "key@pinned_ref" for error messages
_task_info(task) := info if {
	ref := tekton.task_ref(task)
	info := sprintf("%s@%s", [object.get(ref, "key", ""), object.get(ref, "pinned_ref", "")])
}

# Set of digests from trusted builder tasks (used by trusted_parameters rule)
_trusted_build_digests contains digest if {
	some attestation in lib.pipelinerun_attestations
	some build_task in tekton.build_tasks(attestation)
	tekton.is_trusted_task(build_task, _manifests)
	some result in tekton.task_results(build_task)
	some digest in _digests_from_values(lib.result_values(result))
}

# Digests from snapshot components are considered trustworthy
_trusted_build_digests contains digest if {
	some component in input.snapshot.components
	digest := image.parse(component.containerImage).digest
	is_string(digest)
	digest != ""
}

# Digests from SCRIPT_RUNNER_IMAGE_REFERENCE in pre-build tasks are trustworthy
_trusted_build_digests contains digest if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	tekton.is_trusted_task(task, _manifests)
	runner_image_result_value := tekton.task_result(task, _pre_build_run_script_runner_image_result)
	some digest in _digests_from_values({runner_image_result_value})
}

_pre_build_run_script_runner_image_result := "SCRIPT_RUNNER_IMAGE_REFERENCE"

# Extracts SHA256 digests from a set of values using regex patterns
_digests_from_values(values) := {digest |
	some value in values
	some pattern in _digest_patterns
	some digest in regex.find_n(pattern, value, -1)
}

# =============================================================================
# RULES SYSTEM (trusted_task_rules)
# Pattern-based allow/deny rules for task trust.
# This is the preferred system going forward.
# =============================================================================

# Collects trust errors using trusted_task_rules (with Trusted Artifacts)
_trust_errors_rules contains error if {
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

	some untrusted_task in tekton.untrusted_task_refs_rules(chain, _manifests)

	error := _format_trust_error_rules_ta(untrusted_task, dependency_chain)
}

# Collects trust errors using trusted_task_rules (without Trusted Artifacts)
_trust_errors_rules contains error if {
	not _uses_trusted_artifacts
	some untrusted_task in tekton.untrusted_task_refs_rules(lib.tasks_from_pipelinerun, _manifests)
	error := _format_trust_error_rules(untrusted_task)
}

# Formats a denial reason object into a human-readable string
_format_denial_reason(reason) := msg if {
	count(reason.pattern) > 0

	pattern_lines := [sprintf("  - %s", [pattern]) | some pattern in reason.pattern]
	patterns_msg := sprintf("%s\n%s", [reason.type, concat("\n", pattern_lines)])

	messages := object.get(reason, "messages", [])
	count(messages) > 0
	message_lines := [sprintf("  - %s", [m]) | some m in messages]
	msg := sprintf("%s\nMessages:\n%s", [patterns_msg, concat("\n", message_lines)])
} else := msg if {
	count(reason.pattern) > 0

	pattern_lines := [sprintf("  - %s", [pattern]) | some pattern in reason.pattern]
	msg := sprintf("%s\n%s", [reason.type, concat("\n", pattern_lines)])
} else := reason.type

# Format error for rules system with Trusted Artifacts
_format_trust_error_rules_ta(task, dependency_chain) := error if {
	reason := tekton.denial_reason(task, _manifests)
	untrusted_pipeline_task_name := tekton.pipeline_task_name(task)
	untrusted_task_name := tekton.task_name(task)

	reason_msg := _format_denial_reason(reason)

	error := {
		"msg": sprintf(
			# regal ignore:line-length
			"Untrusted version of PipelineTask %q (Task %q) was included in build chain comprised of: %s. The denial reason is: %s",
			[untrusted_pipeline_task_name, untrusted_task_name, concat(", ", dependency_chain), reason_msg],
		),
		"term": untrusted_task_name,
	}
}

# Format error for rules system without Trusted Artifacts
_format_trust_error_rules(task) := error if {
	reason := tekton.denial_reason(task, _manifests)
	untrusted_pipeline_task_name := tekton.pipeline_task_name(task)
	untrusted_task_name := tekton.task_name(task)
	untrusted_task_info := _task_info(task)

	reason_msg := _format_denial_reason(reason)

	error := {
		"msg": sprintf(
			# regal ignore:line-length
			"PipelineTask %q uses an untrusted task reference: %s. The denial reason is: %s",
			[untrusted_pipeline_task_name, untrusted_task_info, reason_msg],
		),
		"term": untrusted_task_name,
	}
}

# =============================================================================
# BEGIN LEGACY SYSTEM (trusted_tasks)
# Explicit allow list with expiry dates.
# DELETE THIS ENTIRE SECTION when removing legacy support.
# =============================================================================

# Collects trust errors using legacy trusted_tasks (with Trusted Artifacts)
_trust_errors_legacy contains error if {
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

	some untrusted_task in tekton.untrusted_task_refs_legacy(chain)

	error := _format_trust_error_legacy_ta(untrusted_task, dependency_chain)
}

# Collects trust errors using legacy trusted_tasks (without Trusted Artifacts)
_trust_errors_legacy contains error if {
	not _uses_trusted_artifacts
	some untrusted_task in tekton.untrusted_task_refs_legacy(lib.tasks_from_pipelinerun)
	error := _format_trust_error_legacy(untrusted_task)
}

# Format error for legacy system with Trusted Artifacts
_format_trust_error_legacy_ta(task, dependency_chain) := error if {
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

# Format error for legacy system without Trusted Artifacts
_format_trust_error_legacy(task) := error if {
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

# =============================================================================
# END LEGACY SYSTEM
# =============================================================================
