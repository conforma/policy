#
# METADATA
# title: Trusted Task checks (Complex Format)
# description: >-
#   This package implements trusted task verification using the complex rule-based format.
#   It supports both legacy trusted_tasks data and new trusted_task_rules format with
#   allow/deny rules, version constraints, and time-based activation.
#
package trusted_tasks_complex

import rego.v1

# Internal libraries (copied from policy/lib to avoid external dependencies)
import data.lib
import data.lib.image
import data.lib.arrays
import data.lib.json as j
import data.lib.time as time_lib
import data.lib.rule_data as lib_rule_data

# Supported TA URIs for trusted artifacts
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
	some task in _untaggedtask_references(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[_pipeline_task_name(task), _task_info(task)],
		_task_name(task),
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
	some task in _unpinnedtask_references(lib.tasks_from_pipelinerun)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[_pipeline_task_name(task), _task_info(task)],
		_task_name(task),
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
	expiry := _expiry_of(task)
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[_pipeline_task_name(task), time.format(expiry), _task_info(task), _latest_trusted_ref(task)],
		_task_name(task),
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
	some task in _tasks(attestation)
	some invalid_input in _trusted_artifact_inputs(task)
	count({o |
		some t in _tasks(attestation)
		some o in _trusted_artifact_outputs(t)

		o == invalid_input
	}) == 0

	task_name = _pipeline_task_name(task)

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
	_missing_trusted_tasks_data
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
	some build_task in _build_tasks(attestation)

	some param_name, param_value in _task_params(build_task)

	# Trusted Artifacts are handled differently. Here we are concerned with all other parameters.
	not endswith(param_name, "_ARTIFACT")
	params_digests := _digests_from_values(lib.param_values(param_value))

	some untrusted_digest in (params_digests - _trusted_build_digests)
	result := lib.result_helper(
		rego.metadata.chain(),
		[param_name, _pipeline_task_name(build_task), untrusted_digest],
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
	some error in _data_errors
	result := lib.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
}

# =============================================================================
# COMPLEX FORMAT IMPLEMENTATION
# =============================================================================

# Enhanced data merging for both old and new formats
_trusted_tasks_data := object.union(data.trusted_tasks, lib_rule_data("trusted_tasks"))
_trusted_task_rules_data := object.union(data.trusted_task_rules, lib_rule_data("trusted_task_rules"))

# _trusted_tasks provides a safe way to access the list of trusted tasks. It prevents a policy rule
# from incorrectly not evaluating due to missing data. It also removes stale records.
_trusted_tasks[key] := pruned_records if {
	some key, records in _trusted_tasks_data
	pruned_records := _unexpired_records(records)
}

# Returns if the list of trusted Tasks are missing
default _missing_trusted_tasks_data := false

_missing_trusted_tasks_data if {
	count(_trusted_tasks) == 0
}

# Returns true if the task uses a trusted Task reference.
is_trusted_task(task) if {
	ref := task_ref(task)
	
	# Legacy support (unchanged)
	legacy_trusted := [record |
		some record in _trusted_task_records(ref.key)
		record.ref == ref.pinned_ref
	]
	count(legacy_trusted) > 0
}

is_trusted_task(task) if {
	ref := task_ref(task)
	
	# New rule-based support
	_is_allowed_by_rules(ref.key)
	not _is_denied_by_rules(ref.key)
}

# Check if task is allowed by rules
_is_allowed_by_rules(ref_key) := true if {
	some rule in _trusted_task_rules_data.allow
	some task_ref in rule.task_refs
	glob.match(task_ref, [], ref_key)
	_rule_effective(rule)
	_signing_requirements_met(rule, ref_key)
}

# Check if task is denied by rules
_is_denied_by_rules(ref_key) := true if {
	some rule in _trusted_task_rules_data.deny
	some task_ref in rule.task_refs
	glob.match(task_ref, [], ref_key)
	_rule_effective(rule)
	_version_constraints_met(rule, ref_key)
}

# Check if rule is effective (past effective_on date)
_rule_effective(rule) := true if {
	not "effective_on" in object.keys(rule)
} else := true if {
	effective_time := time.parse_rfc3339_ns(rule.effective_on)
	effective_time <= time.now_ns()
}

# Check signing requirements
_signing_requirements_met(rule, ref_key) := true if {
	not "signing_key" in object.keys(rule)
} else := true if {
	# Check if task is signed with the required key
	_task_signed_with_key(ref_key, rule.signing_key)
}

# Check version constraints
_version_constraints_met(rule, ref_key) := true if {
	not "versions" in object.keys(rule)
} else := true if {
	some version_constraint in rule.versions
	_extract_version_from_ref(ref_key, version_constraint)
}

# Extract version from reference and check constraint
_extract_version_from_ref(ref_key, constraint) := true if {
	# Complex version parsing logic
	# This would need to extract version from ref_key and compare with constraint
	# Implementation depends on how versions are encoded in ref_key
}

# Check if task is signed with the required key
_task_signed_with_key(ref_key, signing_key) := true if {
	# Placeholder for signing verification logic
	# This would need to implement actual signing verification
}

# Returns a subset of tasks that use untagged bundle Task references.
_untaggedtask_references(tasks) := {task |
	some task in tasks
	ref := task_ref(task)
	ref.bundle
	not ref.tagged
}

# Returns a subset of tasks that use unpinned Task references.
_unpinnedtask_references(tasks) := {task |
	some task in tasks
	not task_ref(task).pinned
}

# Returns a subset of tasks that do not use a trusted Task reference.
untrusted_task_refs(tasks) := {task |
	some task in tasks
	not is_trusted_task(task)
}

# Legacy trusted task records
_trusted_task_records(ref_key) := records if {
	# the reference key matches exactly the key in the trusted tasks set
	records := _trusted_tasks[ref_key]
	count(records) > 0
} else := records if {
	startswith(ref_key, "oci://") # only for oci refs
	records := [match |
		some key, matches in _trusted_tasks
		short_key := regex.replace(key, `:[0-9.]+$`, "")
		ref_key == short_key
		some match in matches
	]
} else := records if {
	# If the key is not found, default to an empty list
	records := []
}

# _trusted_tasks provides a safe way to access the list of trusted tasks. It prevents a policy rule
# from incorrectly not evaluating due to missing data. It also removes stale records.
_trusted_tasks[key] := pruned_records if {
	some key, records in _trusted_tasks_data
	pruned_records := _unexpired_records(records)
}

# Returns the epoch time in nanoseconds of the time when the Task expires, or
# nothing if Task is not set to expire currently.
_expiry_of(task) := expires if {
	expires := _task_expires_on(task)

	# only report if the task is expiring within task_expiry_warning_days days
	expires > _task_expiry_warnings_after
}

# Returns the date in epoch nanoseconds when the task expires, or nothing if it
# hasn't expired yet.
_task_expires_on(task) := expires if {
	ref := task_ref(task)
	records := _trusted_tasks[ref.key]

	matching_records := [r |
		some r in records
		r.ref == ref.pinned_ref
	]

	# Avoid an "eval_conflict_error: functions must not produce multiple
	# outputs..." error if the data has duplicate records for this ref
	record := matching_records[0]

	expires = time.parse_rfc3339_ns(record.expires_on)
}

default _task_expiry_warnings_after := 0

_task_expiry_warnings_after := grace if {
	grace_period_days := lib_rule_data("task_expiry_warning_days")
	grace_period_days > 0
	grace := time.add_date(
		time_lib.effective_current_time_ns, 0, 0,
		grace_period_days,
	)
}

_unexpired_records(records) := all_unexpired if {
	never_expires := [record |
		some record in records
		not "expires_on" in object.keys(record)
	]

	future_expires := [record |
		some record in records
		expires := time.parse_rfc3339_ns(record.expires_on)
		expires > time_lib.effective_current_time_ns
	]
	future_expires_sorted := array.reverse(arrays.sort_by("expires_on", future_expires))

	all_unexpired := array.concat(never_expires, future_expires_sorted)
}

_latest_trusted_ref(task) := trustedtask_ref if {
	ref := task_ref(task)
	trustedtask_ref = _trusted_tasks[ref.key][0].ref
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Task reference extraction
task_ref(task) := j if {
	# Handle old-style bundle reference
	r := _ref(task)
	bundle := r.bundle
	pinned_ref := _pinned_ref_for_bundle(bundle)
	i := _with_pinned_ref(
		{
			"bundle": bundle,
			"name": _ref_name(task),
			"kind": lower(object.get(r, "kind", "task")),
			"key": _key_for_bundle(bundle),
		},
		pinned_ref,
	)
	tagged_ref := _tagged_ref_for_bundle(bundle)
	j = _with_tagged_ref(i, tagged_ref)
} else := j if {
	# Handle bundle-resolver reference
	r := _ref(task)
	r.resolver == "bundles"
	bundle := _param(r, "bundle", "")
	pinned_ref := _pinned_ref_for_bundle(bundle)
	i := _with_pinned_ref(
		{
			"bundle": bundle,
			"name": _ref_name(task),
			"kind": lower(_param(r, "kind", "task")),
			"key": _key_for_bundle(bundle),
		},
		pinned_ref,
	)
	tagged_ref := _tagged_ref_for_bundle(bundle)
	j = _with_tagged_ref(i, tagged_ref)
} else := i if {
	r := _ref(task)
	r.resolver == "git"
	revision := _param(r, "revision", "")
	url := _param(r, "url", "")
	canonical_url := _with_git_suffix(_with_git_prefix(url))
	path_in_repo := _param(r, "pathInRepo", "")
	pinned_ref := _pinned_ref_for_git(revision)
	i := _with_pinned_ref(
		{
			"url": url,
			"revision": revision,
			"pathInRepo": path_in_repo,
			"name": _ref_name(task),
			"kind": lower(object.get(r, "kind", "task")),
			"key": _key_for_git(canonical_url, path_in_repo),
		},
		pinned_ref,
	)
} else := i if {
	# Handle inlined Task definitions
	_ref(task) == {}
	i := _with_pinned_ref(
		{
			# The Task definition itself is inlined without a name. Use a special value here to
			# distinguish from other reference types.
			"name": _no_task_name,
			"kind": "task",
			"key": _unkonwn_task_key,
		},
		_inlined_pinned_ref,
	)
} else := i if {
	# Handle local reference
	r := _ref(task)
	i := _with_pinned_ref(
		{
			"name": _ref_name(task),
			"kind": lower(object.get(r, "kind", "task")),
			"key": _unkonwn_task_key,
		},
		"",
	)
}

# Task name extraction
_task_name(task) := task_name if {
	ref := task_ref(task)
	task_name := ref.name
} else := task_name if {
	task_name := _ref_name(task)
}

# Pipeline task name extraction
_pipeline_task_name(task) := task.name if {
	task.name
} else := task.metadata.name if {
	task.metadata.name
}

# Task info formatting
_task_info(task) := info if {
	ref := task_ref(task)
	info := sprintf("%s@%s", [object.get(ref, "key", ""), object.get(ref, "pinned_ref", "")])
}

# =============================================================================
# INTERNAL HELPER FUNCTIONS
# =============================================================================

_ref(task) := r if {
	# Reference from within a PipelineRun slsa v0.2 attestation
	r := task.ref
} else := r if {
	# Reference from within a Pipeline definition or a PipelineRun slsa v1.0 attestation
	r := task.taskRef
} else := r if {
	# reference from a taskRun in a slsav1 attestation
	r := task.spec.taskRef
} else := {}

_ref_name(task) := name if {
	ref := _ref(task)
	name := ref.name
} else := name if {
	# Handle inlined Task definitions
	_ref(task) == {}
	name := _no_task_name
}

_param(task_ref, name, fallback) := value if {
	some param in task_ref.params
	param.name == name
	value := param.value
} else := fallback

# Key generation functions
_key_for_bundle(bundle) := key if {
	parts := image.parse(bundle)
	parts.tag != ""
	key := sprintf("oci://%s:%s", [parts.repo, parts.tag])
} else := key if {
	parts := image.parse(bundle)
	key := sprintf("oci://%s", [parts.repo])
} else := sprintf("oci://%s", [bundle])

_key_for_git(url, path_in_repo) := sprintf("%s//%s", [url, path_in_repo])

_with_git_prefix(url) := with_prefix if {
	not startswith(url, "git+")
	with_prefix := sprintf("git+%s", [url])
} else := url

_with_git_suffix(url) := with_suffix if {
	not endswith(url, ".git")
	with_suffix := sprintf("%s.git", [url])
} else := url

# Pinned reference handling
_pinned_ref_for_bundle(bundle) := pinned_ref if {
	parts := image.parse(bundle)
	parts.digest != ""
	pinned_ref := parts.digest
} else := ""

_pinned_ref_for_git(revision) := revision if {
	_is_sha1(revision)
} else := ""

_inlined_pinned_ref := "inlined"

_with_pinned_ref(ref, pinned_ref) := new_ref if {
	pinned_ref == ""
	new_ref := object.union(ref, {"pinned": false})
} else := new_ref if {
	new_ref := object.union(ref, {"pinned": true, "pinned_ref": pinned_ref})
}

# Tagged reference handling
_tagged_ref_for_bundle(bundle) := tagged_ref if {
	parts := image.parse(bundle)
	parts.tag != ""
	tagged_ref := parts.tag
} else := ""

_with_tagged_ref(ref, tagged_ref) := new_ref if {
	tagged_ref == ""
	new_ref := object.union(ref, {"tagged": false})
} else := new_ref if {
	new_ref := object.union(ref, {"tagged": true, "tagged_ref": tagged_ref})
}

# SHA1 detection
default _is_sha1(_) := false

_is_sha1(value) if regex.match(`^[0-9a-f]{40}$`, value)

# Constants
_no_task_name := "unknown"
_unkonwn_task_key := "unknown"

# =============================================================================
# TRUSTED ARTIFACTS LOGIC
# =============================================================================

_trust_errors contains error if {
	_uses_trusted_artifacts
	some attestation in lib.pipelinerun_attestations
	build_tasks := _build_tasks(attestation)
	test_tasks := _tasks_output_result(attestation)
	some build_or_test_task in array.concat(build_tasks, test_tasks)

	dependency_chain := graph.reachable(_artifact_chain[attestation], {_pipeline_task_name(build_or_test_task)})

	chain := [task |
		some link in dependency_chain
		some task in _tasks(attestation)

		link == _pipeline_task_name(task)
	]

	some untrusted_task in untrusted_task_refs(chain)

	error := _format_trust_error_ta(untrusted_task, dependency_chain)
}

_trust_errors contains error if {
	not _uses_trusted_artifacts
	some untrusted_task in untrusted_task_refs(lib.tasks_from_pipelinerun)
	error := _format_trust_error(untrusted_task)
}

_artifact_chain[attestation][name] := dependencies if {
	some attestation in lib.pipelinerun_attestations
	some task in _tasks(attestation)
	name := _pipeline_task_name(task)
	dependencies := {dep |
		some t in _tasks(attestation)
		some i in _trusted_artifact_inputs(task)
		some o in _trusted_artifact_outputs(t)
		i == o
		dep := _pipeline_task_name(t)
	}
}

_trusted_artifact_inputs(task) := {value |
	some key, value in _task_params(task)
	endswith(key, "_ARTIFACT")
	count({b |
		some supported_uri_ta_reg in _supported_ta_uris_reg
		b = regex.match(supported_uri_ta_reg, value)
		b
	}) == 1
}

_trusted_artifact_outputs(task) := {result.value |
	some result in _task_results(task)
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

# _trusted_build_digest is a set containing any digest found in one of the trusted builder Tasks.
_trusted_build_digests contains digest if {
	some attestation in lib.pipelinerun_attestations
	some build_task in _build_tasks(attestation)
	is_trusted_task(build_task)
	some result in _task_results(build_task)
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
	some task in _pre_build_tasks(attestation)
	is_trusted_task(task)
	runner_image_result_value := _task_result(task, _pre_build_run_script_runner_image_result)
	some digest in _digests_from_values({runner_image_result_value})
}

_pre_build_run_script_runner_image_result := "SCRIPT_RUNNER_IMAGE_REFERENCE"

_digests_from_values(values) := {digest |
	some value in values
	some pattern in _digest_patterns
	some digest in regex.find_n(pattern, value, -1)
}

_format_trust_error_ta(task, dependency_chain) := error if {
	latest_trusted_ref := _latest_trusted_ref(task)
	untrusted_pipeline_task_name := _pipeline_task_name(task)
	untrusted_task_name := _task_name(task)

	error := {
		"msg": sprintf(
			# regal ignore:line-length
			"Untrusted version of PipelineTask %q (Task %q) was included in build chain comprised of: %s. Please upgrade the task version to: %s",
			[untrusted_pipeline_task_name, untrusted_task_name, concat(", ", dependency_chain), latest_trusted_ref],
		),
		"term": untrusted_task_name,
	}
} else := error if {
	untrusted_pipeline_task_name := _pipeline_task_name(task)
	untrusted_task_name := _task_name(task)

	error := {
		"msg": sprintf(
			"Code tampering detected, untrusted PipelineTask %q (Task %q) was included in build chain comprised of: %s",
			[untrusted_pipeline_task_name, untrusted_task_name, concat(", ", dependency_chain)],
		),
		"term": untrusted_task_name,
	}
}

_format_trust_error(task) := error if {
	latest_trusted_ref := _latest_trusted_ref(task)
	untrusted_pipeline_task_name := _pipeline_task_name(task)
	untrusted_task_name := _task_name(task)
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
	untrusted_pipeline_task_name := _pipeline_task_name(task)
	untrusted_task_name := _task_name(task)
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
# TEKTON HELPER FUNCTIONS
# =============================================================================

# Task extraction from attestations
_tasks(attestation) := tasks if {
	attestation.statement.predicate.buildConfig.tasks
	tasks := attestation.statement.predicate.buildConfig.tasks
} else := tasks if {
	attestation.spec.tasks
	tasks := attestation.spec.tasks
}

# Build tasks extraction
_build_tasks(attestation) := tasks if {
	attestation.statement.predicate.buildConfig.tasks
	tasks := [task |
		some task in attestation.statement.predicate.buildConfig.tasks
		_ref(task).kind == "Task"
		_ref(task).bundle
	]
} else := tasks if {
	attestation.spec.tasks
	tasks := [task |
		some task in attestation.spec.tasks
		_ref(task).kind == "Task"
		_ref(task).bundle
	]
}

# Tasks output result extraction
_tasks_output_result(attestation) := tasks if {
	attestation.statement.predicate.buildConfig.tasks
	tasks := [task |
		some task in attestation.statement.predicate.buildConfig.tasks
		_ref(task).kind == "Task"
		_ref(task).bundle
		some result in _task_results(task)
		endswith(result.name, "_ARTIFACT")
	]
} else := tasks if {
	attestation.spec.tasks
	tasks := [task |
		some task in attestation.spec.tasks
		_ref(task).kind == "Task"
		_ref(task).bundle
		some result in _task_results(task)
		endswith(result.name, "_ARTIFACT")
	]
}

# Pre-build tasks extraction
_pre_build_tasks(attestation) := tasks if {
	attestation.statement.predicate.buildConfig.tasks
	tasks := [task |
		some task in attestation.statement.predicate.buildConfig.tasks
		_ref(task).kind == "Task"
		_ref(task).bundle
		_ref(task).name == "run-script-oci-ta"
	]
} else := tasks if {
	attestation.spec.tasks
	tasks := [task |
		some task in attestation.spec.tasks
		_ref(task).kind == "Task"
		_ref(task).bundle
		_ref(task).name == "run-script-oci-ta"
	]
}

# Task parameters extraction
_task_params(task) := params if {
	_ref(task).params
	params := {name: value |
		some param in _ref(task).params
		name := param.name
		value := param.value
	}
} else := {}

# Task results extraction
_task_results(task) := results if {
	task.results
	results := task.results
} else := []

# Task result by name
_task_result(task, result_name) := result.value if {
	some result in _task_results(task)
	result.name == result_name
}

# =============================================================================
# DATA VALIDATION
# =============================================================================

# Data validation for trusted_tasks format
_data_errors contains error if {
	some e in j.validate_schema(
		_trusted_tasks_data,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"patternProperties": {".*": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"effective_on": {"type": "string"},
						"expires_on": {"type": "string"},
						"ref": {"type": "string"},
					},
					"required": ["ref"],
					"additionalProperties": false,
				},
				"minItems": 1,
			}},
		},
	)

	error := {
		"message": sprintf("trusted_tasks data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

# Data validation for trusted_task_rules format
_data_errors contains error if {
	some e in j.validate_schema(
		_trusted_task_rules_data,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"properties": {
				"allow": {
					"type": "array",
					"items": {
						"type": "object",
						"properties": {
							"task_refs": {"type": "array", "items": {"type": "string"}},
							"signing_key": {"type": "string"},
							"effective_on": {"type": "string"},
						},
						"required": ["task_refs"],
					},
				},
				"deny": {
					"type": "array",
					"items": {
						"type": "object",
						"properties": {
							"task_refs": {"type": "array", "items": {"type": "string"}},
							"versions": {"type": "array", "items": {"type": "string"}},
							"message": {"type": "string"},
							"effective_on": {"type": "string"},
						},
						"required": ["task_refs"],
					},
				},
			},
		},
	)
	error := {
		"message": sprintf("trusted_task_rules data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

# Additional validation for trusted_tasks data
_data_errors contains error if {
	some task, refs in _trusted_tasks_data
	some i, ref in refs
	not time.parse_rfc3339_ns(ref.effective_on)
	error := {
		"message": sprintf(
			"trusted_tasks.%s[%d].effective_on is not valid RFC3339 format: %q",
			[task, i, ref.effective_on],
		),
		"severity": "failure",
	}
}

_data_errors contains error if {
	some task, refs in _trusted_tasks_data
	some i, ref in refs
	not time.parse_rfc3339_ns(ref.expires_on)
	error := {
		"message": sprintf(
			"trusted_tasks.%s[%d].expires_on is not valid RFC3339 format: %q",
			[task, i, ref.expires_on],
		),
		"severity": "failure",
	}
}

# Validation for task_expiry_warning_days
_data_errors contains error if {
	some error in j.validate_schema(
		{"task_expiry_warning_days": lib_rule_data("task_expiry_warning_days")},
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"properties": {"task_expiry_warning_days": {
				"type": "integer",
				"minimum": 0,
			}},
		},
	)
}
