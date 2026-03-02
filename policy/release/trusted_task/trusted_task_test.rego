package trusted_task_test

import rego.v1

import data.lib
import data.trusted_task

test_success if {
	att_no_ta := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [
				newest_bundle_pipeline_task,
				newest_git_pipeline_task,
			]},
		},
	}}

	lib.assert_empty(trusted_task.warn | trusted_task.deny, expected) with data.trusted_tasks as trusted_tasks_data
		with input.attestations as [att_no_ta, attestation_ta]
}

test_pinned_warning if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [
				trusted_bundle_pipeline_task,
				unpinned_bundle_pipeline_task,
				trusted_git_pipeline_task,
				unpinned_git_pipeline_task,
			]},
		},
	}}

	expected := {
		{
			"code": "trusted_task.pinned",
			# regal ignore:line-length
			"msg": `Pipeline task "unpinned-honest-abe-p" uses an unpinned task reference, git+git.local/repo.git//tasks/honest-abe.yaml@`, "term": "honest-abe",
		},
		{
			"code": "trusted_task.pinned",
			# regal ignore:line-length
			"msg": `Pipeline task "unpinned-trusty-p" uses an unpinned task reference, oci://registry.local/trusty:1.0@`, "term": "trusty",
		},
	}

	lib.assert_equal_results(trusted_task.warn, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_tagged_warning if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [
				trusted_bundle_pipeline_task,
				untagged_bundle_pipeline_task,
			]},
		},
	}}

	expected := {{
		"code": "trusted_task.tagged",
		# regal ignore:line-length
		"msg": "Pipeline task \"untagged-trusty-p\" uses an untagged task reference, oci://registry.local/trusty@sha256:digest", "term": "trusty",
	}}

	lib.assert_equal_results(trusted_task.warn, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_outdated_warning if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [
				trusted_bundle_pipeline_task,
				outdated_bundle_pipeline_task,
				trusted_git_pipeline_task,
				outdated_git_pipeline_task,
			]},
		},
	}}

	expected := {
		{
			"code": "trusted_task.current",
			# regal ignore:line-length
			"msg": `A newer version of task "outdated-honest-abe-p" exists. Please update before 2099-01-01T00:00:00Z. The current bundle is "git+git.local/repo.git//tasks/honest-abe.yaml@37ef630394794f28142224295851a45eea5c63ae" and the latest bundle ref is "48df630394794f28142224295851a45eea5c63ae"`,
			"term": "honest-abe",
		},
		{
			"code": "trusted_task.current",
			# regal ignore:line-length
			"msg": `A newer version of task "outdated-trusty-p" exists. Please update before 2099-01-01T00:00:00Z. The current bundle is "oci://registry.local/trusty:1.0@sha256:outdated-digest" and the latest bundle ref is "sha256:digest"`,
			"term": "trusty",
		},
	}

	lib.assert_equal_results(trusted_task.warn, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_trusted_violation if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [
				trusted_bundle_pipeline_task,
				untagged_bundle_pipeline_task,
				outdated_bundle_pipeline_task,
				unknown_bundle_pipeline_task,
				expired_bundle_pipeline_task,
				trusted_git_pipeline_task,
				outdated_git_pipeline_task,
				unknown_git_pipeline_task,
				expired_git_pipeline_task,
				inlined_pipeline_task,
			]},
		},
	}}

	expected := {
		{
			"code": "trusted_task.trusted",
			"msg": `PipelineTask "crook-p" uses an untrusted task reference: oci://registry.local/crook:1.0@sha256:digest`,
			"term": "crook",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": `PipelineTask "expired-honest-abe-p" uses an untrusted task reference: git+git.local/repo.git//tasks/honest-abe.yaml@26ef630394794f28142224295851a45eea5c63ae. Please upgrade the task version to: 48df630394794f28142224295851a45eea5c63ae`,
			"term": "honest-abe",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": `PipelineTask "expired-trusty-p" uses an untrusted task reference: oci://registry.local/trusty:1.0@sha256:expired-digest. Please upgrade the task version to: sha256:digest`,
			"term": "trusty",
		},
		{
			# regal ignore:line-length
			"code": "trusted_task.trusted", "msg": `PipelineTask "inlined-p" uses an untrusted task reference: <UNKNOWN>@<INLINED>`,
			"term": "<NAMELESS>",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": `PipelineTask "untrusted-lawless-p" uses an untrusted task reference: git+git.local/repo.git//tasks/lawless.yaml@37ef630394794f28142224295851a45eea5c63ae`,
			"term": "lawless",
		},
	}

	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as trusted_tasks_data
}

test_trusted_artifact_tampering if {
	evil_attestation := json.patch(attestation_ta, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/1/ref/bundle",
		"value": "registry.io/evil/bundle@sha256:cde",
	}])

	expected := {
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": `Code tampering detected, untrusted PipelineTask "task_b" (Task "TaskB") was included in build chain comprised of: task_a, task_b, task_c`,
			"term": "TaskB",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": `Code tampering detected, untrusted PipelineTask "task_b" (Task "TaskB") was included in build chain comprised of: task_b, task_c, task_test_a`,
			"term": "TaskB",
		},
	}

	lib.assert_equal_results(trusted_task.deny, expected) with data.trusted_tasks as trusted_tasks_data
		with input.attestations as [evil_attestation]
}

test_trusted_artifact_outdated if {
	attestation_with_outdated_task := json.patch(attestation_ta, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/1/ref/bundle",
		"value": outdated_bundle,
	}])

	expected := {
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": `Untrusted version of PipelineTask "task_b" (Task "TaskB") was included in build chain comprised of: task_a, task_b, task_c. Please upgrade the task version to: sha256:digest`,
			"term": "TaskB",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": `Untrusted version of PipelineTask "task_b" (Task "TaskB") was included in build chain comprised of: task_b, task_c, task_test_a. Please upgrade the task version to: sha256:digest`,
			"term": "TaskB",
		},
	}

	lib.assert_equal_results(trusted_task.deny, expected) with data.trusted_tasks as trusted_tasks_data
		with input.attestations as [attestation_with_outdated_task]
}

# Test trusted artifacts with deny rules - covers _format_trust_error_rules_ta function
test_trusted_artifact_denied_by_rules if {
	# Deny all trusty tasks via trusted_task_rules
	task_rules := {
		"allow": [{
			"name": "Allow all trusty tasks",
			"pattern": "oci://registry.local/trusty*",
		}],
		"deny": [{
			"name": "Deny trusty 1.0",
			"pattern": "oci://registry.local/trusty:1.0",
			"message": "Version 1.0 is deprecated",
		}],
	}

	# Use the full TA attestation - all tasks use the same bundle so all chains are denied
	# Multiple violations are expected due to overlapping dependency chains
	expected := {
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Untrusted version of PipelineTask \"task_a\" (Task \"TaskA\") was included in build chain comprised of: task_a, task_b, task_c. The denial reason is: deny_rule\n  - oci://registry.local/trusty:1.0\nMessages:\n  - Version 1.0 is deprecated",
			"term": "TaskA",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Untrusted version of PipelineTask \"task_b\" (Task \"TaskB\") was included in build chain comprised of: task_a, task_b, task_c. The denial reason is: deny_rule\n  - oci://registry.local/trusty:1.0\nMessages:\n  - Version 1.0 is deprecated",
			"term": "TaskB",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Untrusted version of PipelineTask \"task_c\" (Task \"TaskC\") was included in build chain comprised of: task_a, task_b, task_c. The denial reason is: deny_rule\n  - oci://registry.local/trusty:1.0\nMessages:\n  - Version 1.0 is deprecated",
			"term": "TaskC",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Untrusted version of PipelineTask \"task_b\" (Task \"TaskB\") was included in build chain comprised of: task_b, task_c, task_test_a. The denial reason is: deny_rule\n  - oci://registry.local/trusty:1.0\nMessages:\n  - Version 1.0 is deprecated",
			"term": "TaskB",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Untrusted version of PipelineTask \"task_c\" (Task \"TaskC\") was included in build chain comprised of: task_b, task_c, task_test_a. The denial reason is: deny_rule\n  - oci://registry.local/trusty:1.0\nMessages:\n  - Version 1.0 is deprecated",
			"term": "TaskC",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Untrusted version of PipelineTask \"task_test_a\" (Task \"TaskTestA\") was included in build chain comprised of: task_b, task_c, task_test_a. The denial reason is: deny_rule\n  - oci://registry.local/trusty:1.0\nMessages:\n  - Version 1.0 is deprecated",
			"term": "TaskTestA",
		},
		{
			"code": "trusted_task.trusted",
			# regal ignore:line-length
			"msg": "Untrusted version of PipelineTask \"task_image_index\" (Task \"TaskA\") was included in build chain comprised of: task_image_index. The denial reason is: deny_rule\n  - oci://registry.local/trusty:1.0\nMessages:\n  - Version 1.0 is deprecated",
			"term": "TaskA",
		},
		{
			"code": "trusted_task.trusted_parameters",
			# regal ignore:line-length
			"msg": "The \"image\" parameter of the \"task_image_index\" PipelineTask includes an untrusted digest: sha256:49a6fd43239ae41643426daefc5239857a1cc1a6f2c1595f88965d7de88efcb9",
		},
	}

	lib.assert_equal_results(trusted_task.deny, expected) with data.trusted_tasks as trusted_tasks_data
		with data.rule_data.trusted_task_rules as task_rules
		with input.attestations as [attestation_ta]
}

# Test that future deny rules produce a warning
test_future_deny_rule_warning if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [trusted_bundle_pipeline_task]},
		},
	}}

	# Task is allowed but a deny rule with future effective_on is present
	task_rules := {
		"allow": [{"name": "Allow all trusty tasks", "pattern": "oci://registry.local/trusty*"}],
		"deny": [{
			"name": "Deny trusty 1.0 in the future",
			"pattern": "oci://registry.local/trusty:1.0*",
			"effective_on": "2099-01-01",
		}],
	}

	expected := {{
		"code": "trusted_task.future_deny_rule",
		# regal ignore:line-length
		"msg": `Task "trusty-p" will be denied by rule pattern "oci://registry.local/trusty:1.0*" starting on 2099-01-01.`,
		"term": "trusty",
	}}

	lib.assert_equal_results(trusted_task.warn, expected) with data.rule_data.trusted_task_rules as task_rules
		with input.attestations as [att]
}

# Test that deny rules without effective_on do not produce a future deny warning
test_future_deny_rule_no_warning_when_already_effective if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [trusted_bundle_pipeline_task]},
		},
	}}

	# Deny rule has no effective_on, so it's already effective (no warning)
	task_rules := {
		"allow": [{"name": "Allow all trusty tasks", "pattern": "oci://registry.local/trusty*"}],
		"deny": [{
			"name": "Deny trusty 1.0",
			"pattern": "oci://registry.local/trusty:1.0*",
		}],
	}

	# No future_deny_rule warning expected (the deny itself will fire, but not the warning)
	results := trusted_task.warn with data.rule_data.trusted_task_rules as task_rules
		with input.attestations as [att]

	count([r | some r in results; r.code == "trusted_task.future_deny_rule"]) == 0
}

test_trusted_artifact_test_tasks if {
	lib.assert_empty(trusted_task.deny) with data.trusted_tasks as trusted_tasks_data
		with input.attestations as [attestation_ta]
}

test_tampered_trusted_artifact_inputs if {
	evil_attestation := json.patch(attestation_ta, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/1/invocation/parameters/F_ARTIFACT",
		"value": "oci:registry.io/repository/image@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}])

	lib.assert_equal_results(trusted_task.deny, {{
		"code": "trusted_task.valid_trusted_artifact_inputs",
		# regal ignore:line-length
		"msg": `Code tampering detected, input "oci:registry.io/repository/image@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" for task "task_b" was not produced by the pipeline as attested.`,
		"term": "oci:registry.io/repository/image@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}}) with data.trusted_tasks as trusted_tasks_data
		with input.attestations as [evil_attestation]
}

test_artifact_chain if {
	expected := {
		"task_a": {"task_b", "task_c"},
		"task_b": {"task_c"},
		"task_c": set(),
		"task_image_index": set(),
		"task_test_a": {"task_b"},
	}

	lib.assert_equal(trusted_task._artifact_chain[attestation_ta], expected) with input.attestations as [attestation_ta]
}

test_trusted_artifact_inputs_from_parameters if {
	task := {"invocation": {"parameters": {
		"param1": "value1",
		"SOME_ARTIFACT": "value2",
		"SOURCE_ARTIFACT": artifact_a,
		# regal ignore:line-length
		"UNEXPECTED_ARTIFACT": "oci:registry.io/repository/image@sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}}}

	lib.assert_equal(trusted_task._trusted_artifact_inputs(task), {artifact_a})
}

test_trusted_artifact_outputs_from_results if {
	task := {"results": [
		{
			"name": "result1",
			"value": "value1",
			"type": "string",
		},
		{
			"name": "SOME_ARTIFACT",
			"value": "value2",
			"type": "string",
		},
		{
			"name": "SOURCE_ARTIFACT",
			"value": artifact_a,
			"type": "string",
		},
		{
			"name": "UNEXPECTED1_ARTIFACT",
			"value": "oci:registry.io/repository/image@sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			"type": "string",
		},
		{
			"name": "UNEXPECTED2_ARTIFACT",
			"value": artifact_a,
			"type": "array",
		},
	]}

	lib.assert_equal(
		trusted_task._trusted_artifact_outputs(task),
		{artifact_a},
	)
}

test_trusted_parameters if {
	evil_attestation := json.patch(attestation_ta, [{
		"op": "add",
		"path": "/statement/predicate/buildConfig/tasks/3/invocation/parameters/image",
		"value": "registry.io/repository/image@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	}])

	lib.assert_equal_results(trusted_task.deny, {{
		"code": "trusted_task.trusted_parameters",
		# regal ignore:line-length
		"msg": `The "image" parameter of the "task_image_index" PipelineTask includes an untrusted digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`,
	}}) with data.trusted_tasks as trusted_tasks_data
		with input.attestations as [evil_attestation]

	# regal ignore:line-length
	fake_component := {"containerImage": "registry.io/repository/image@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}

	# If that same digest was found in the snapshot then we assume that it's not actually evil and therefore permit it
	lib.assert_empty(trusted_task.deny) with data.trusted_tasks as trusted_tasks_data
		with input.attestations as [evil_attestation]
		with input.snapshot.components as [fake_component]
}

test_data_missing if {
	expected := {{"code": "trusted_task.data", "msg": "Missing required trusted_tasks data"}}
	lib.assert_equal_results(trusted_task.deny, expected) with data.trusted_tasks as []
}

test_data_errors if {
	# Data validation happens in tkn.data_errors. Only need to test that errors are propagated.
	bad_data := {"spam": [{"spam": "spam"}]}
	expected := {
		{
			"code": "trusted_task.data_format",
			"msg": "trusted_tasks data has unexpected format: spam.0: Additional property spam is not allowed",
			"severity": "warning",
		},
		{
			"code": "trusted_task.data_format",
			"msg": "trusted_tasks data has unexpected format: spam.0: ref is required",
			"severity": "failure",
		},
	}
	lib.assert_equal_results(trusted_task.deny, expected) with data.trusted_tasks as bad_data
}

################################
# _trusted_build_digests tests #
################################

_mock_run_script_result := {
	"name": "SCRIPT_RUNNER_IMAGE_REFERENCE",
	"value": "registry.io/runner/image@sha256:1111111111111111111111111111111111111111111111111111111111111111",
	"type": "string",
}

_mock_att_with_task(task) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task]},
	},
}}

test_trusted_build_digests_from_run_script_result if {
	# A digest from the SCRIPT_RUNNER_IMAGE_REFERENCE task result in the run-script-oci-ta
	# task appears in _trusted_build_digests if the task is considered a trusted task
	attestation := _mock_att_with_task({
		"ref": {"name": "run-script-oci-ta", "bundle": "registry.local/trusty:1.0@sha256:digest"},
		"results": [_mock_run_script_result],
	})
	expected := {"sha256:1111111111111111111111111111111111111111111111111111111111111111"}
	lib.assert_equal(trusted_task._trusted_build_digests, expected) with input.attestations as [attestation]
		with data.trusted_tasks as trusted_tasks_data
}

test_trusted_build_digests_from_run_script_untrusted if {
	# A digest from the SCRIPT_RUNNER_IMAGE_REFERENCE task result in the run-script-oci-ta
	# task does not appear in _trusted_build_digests if the task is not considered a trusted task
	attestation := _mock_att_with_task({
		"ref": {"name": "run-script-oci-ta", "bundle": "registry.local/unknown:1.0@sha256:digest"},
		"results": [_mock_run_script_result],
	})
	lib.assert_empty(trusted_task._trusted_build_digests) with input.attestations as [attestation]
		with data.trusted_tasks as trusted_tasks_data
}

test_trusted_build_digests_from_run_script_no_result if {
	# A digest from the some other task result in the run-script-oci-ta task does not appear
	# in _trusted_build_digests even if the task is not considered a trusted task
	results := json.patch(_mock_run_script_result, [{"op": "add", "path": "/name", "value": "SOME_OTHER_NAME"}])
	attestation := _mock_att_with_task({
		"ref": {"name": "run-script-oci-ta", "bundle": "registry.local/trusty:1.0@sha256:digest"},
		"results": [results],
	})
	lib.assert_equal(trusted_task._trusted_build_digests, set()) with input.attestations as [attestation]
		with data.trusted_tasks as trusted_tasks_data
}

test_trusted_build_digests_from_build_task_results if {
	# A digest from the the IMAGE_DIGEST build task result appears in _trusted_build_digests
	# if the build task is considered a trusted task
	attestation := _mock_att_with_task({
		"ref": {"name": "some-task", "bundle": "registry.local/trusty:1.0@sha256:digest"},
		"results": [
			{"name": "SOME_IMAGE_URL", "value": "registry.io/whatever/image", "type": "string"},
			# regal ignore:line-length
			{"name": "SOME_IMAGE_DIGEST", "value": "sha256:2222222222222222222222222222222222222222222222222222222222222222", "type": "string"},
		],
	})
	expected := {"sha256:2222222222222222222222222222222222222222222222222222222222222222"}
	lib.assert_equal(trusted_task._trusted_build_digests, expected) with input.attestations as [attestation]
		with data.trusted_tasks as trusted_tasks_data
}

test_trusted_build_digests_from_snapshot_components if {
	# Digests present in the snapshot components should appear in _trusted_build_digests
	components := [
		# regal ignore:line-length
		{"containerImage": "registry.io/repository/image1@sha256:3333333333333333333333333333333333333333333333333333333333333333"},
		# regal ignore:line-length
		{"containerImage": "registry.io/repository/image2@sha256:4444444444444444444444444444444444444444444444444444444444444444"},
	]
	expected := {
		"sha256:3333333333333333333333333333333333333333333333333333333333333333",
		"sha256:4444444444444444444444444444444444444444444444444444444444444444",
	}
	lib.assert_equal(trusted_task._trusted_build_digests, expected) with input.snapshot.components as components
}

#########################################
# Pipeline Tasks using bundles resolver #
#########################################

trusted_bundle_pipeline_task := {
	"name": "trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:digest"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

newest_bundle_pipeline_task := trusted_bundle_pipeline_task

outdated_bundle_pipeline_task := {
	"name": "outdated-trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:outdated-digest"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

expired_bundle_pipeline_task := {
	"name": "expired-trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:expired-digest"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

unpinned_bundle_pipeline_task := {
	"name": "unpinned-trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty:1.0"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

untagged_bundle_pipeline_task := {
	"name": "untagged-trusty-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/trusty@sha256:digest"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]},
}

unknown_bundle_pipeline_task := {
	"name": "crook-p",
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": "registry.local/crook:1.0@sha256:digest"},
		{"name": "name", "value": "crook"},
		{"name": "kind", "value": "task"},
	]},
}

#####################################
# Pipeline Tasks using git resolver #
#####################################

trusted_git_pipeline_task := {
	"name": "honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "48df630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

newest_git_pipeline_task := trusted_git_pipeline_task

outdated_git_pipeline_task := {
	"name": "outdated-honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

expired_git_pipeline_task := {
	"name": "expired-honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "26ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

unpinned_git_pipeline_task := {
	"name": "unpinned-honest-abe-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "main"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "honest-abe"}}},
}

unknown_git_pipeline_task := {
	"name": "untrusted-lawless-p",
	"ref": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/lawless.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]},
	"invocation": {"environment": {"labels": {"tekton.dev/task": "lawless"}}},
}

##########################
# Inlined Pipeline Tasks #
##########################

inlined_pipeline_task := {
	"name": "inlined-p",
	"ref": {},
}

###########################
# Trusted Artifacts data #
###########################

artifact_a := "oci:registry.io/repository/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

artifact_b := "oci:registry.io/repository/image@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

artifact_c := "oci:registry.io/repository/image@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

artifact_d := "oci:registry.io/repository/image@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

image_a_digest := "sha256:49a6fd43239ae41643426daefc5239857a1cc1a6f2c1595f88965d7de88efcb9"

image_index_digest := "sha256:6e69e396950defe6ff7981636e30498f99128310a4ee37a87c48729888cb77b3"

outdated_bundle := "registry.local/trusty:1.0@sha256:outdated"

trusted_bundle := "registry.local/trusty:1.0@sha256:digest"

task_image_index := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_image_index"}},
	"invocation": {"parameters": {"image": sprintf("registry.io/repository/image@%s", [image_a_digest])}},
	"results": [
		{
			"name": "IMAGE_URL",
			"value": "registry.io/repository/image",
			"type": "string",
		},
		{
			"name": "IMAGE_DIGEST",
			"value": image_index_digest,
			"type": "string",
		},
	],
	"ref": {"name": "TaskA", "kind": "Task", "bundle": trusted_bundle},
}

task_a := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_a"}},
	"invocation": {"parameters": {"B_ARTIFACT": artifact_b, "D_ARTIFACT": artifact_d}},
	"results": [
		{
			"name": "IMAGE_URL",
			"value": "registry.io/repository/image",
			"type": "string",
		},
		{
			"name": "IMAGE_DIGEST",
			"value": image_a_digest,
			"type": "string",
		},
	],
	"ref": {"name": "TaskA", "kind": "Task", "bundle": trusted_bundle},
}

task_b := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_b"}},
	"invocation": {"parameters": {"C_ARTIFACT": artifact_c}},
	"results": [{
		"name": "B_ARTIFACT",
		"value": artifact_b,
		"type": "string",
	}],
	"ref": {"name": "TaskB", "kind": "Task", "bundle": trusted_bundle},
}

task_c := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_c"}},
	"results": [
		{
			"name": "C_ARTIFACT",
			"value": artifact_c,
			"type": "string",
		},
		{
			"name": "D_ARTIFACT",
			"value": artifact_d,
			"type": "string",
		},
	],
	"ref": {"name": "TaskC", "kind": "Task", "bundle": trusted_bundle},
}

task_test_a := {
	"metadata": {"labels": {"tekton.dev/pipelineTask": "task_test_a"}},
	"invocation": {"parameters": {"B_ARTIFACT": artifact_b}},
	"results": [{
		"name": "TEST_OUTPUT",
		"value": `{"FAILED": "1"}`,
		"type": "string",
	}],
	"ref": {"name": "TaskTestA", "kind": "Task", "bundle": trusted_bundle},
}

attestation_ta := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [task_a, task_b, task_c, task_image_index, task_test_a]},
	},
}}

######################
# Trusted Tasks data #
######################

trusted_tasks_data := {
	"oci://registry.local/trusty:1.0": [
		{
			"ref": "sha256:digest",
			"effective_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:outdated-digest",
			"effective_on": "2024-01-01T00:00:00Z",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:expired-digest",
			"effective_on": "2023-01-01T00:00:00Z",
			"expires_on": "2024-01-01T00:00:00Z",
		},
	],
	"git+git.local/repo.git//tasks/honest-abe.yaml": [
		{
			"ref": "48df630394794f28142224295851a45eea5c63ae",
			"effective_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "37ef630394794f28142224295851a45eea5c63ae",
			"effective_on": "2024-01-01T00:00:00Z",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "26ef630394794f28142224295851a45eea5c63ae",
			"effective_on": "2023-01-01T00:00:00Z",
			"expires_on": "2024-01-01T00:00:00Z",
		},
	],
}

#####################################################
# Functional tests for trusted_task_rules
# Based on test cases defined in https://github.com/konflux-ci/architecture/blob/main/ADR/0053-trusted-task-model.md
#
# Note: Version-based tests (E1, E2, E3, I1) are skipped as versioning is not yet implemented.
# Git reference test (J1) is marked as TODO/TBD.
#####################################################

#####################################################
# 1. Coexistence With trusted_tasks (A1-A3)
#####################################################

# A1 — On trusted_tasks, no rules → trusted
# Task is in trusted_tasks, trusted_task_rules is empty → should be trusted via legacy fallback
test_on_trusted_tasks_no_rules_trusted if {
	rules_trusted_tasks_data := {"oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4": [{"ref": "sha256:abc123"}]}

	trusted_task_rules_data := {
		"allow": [],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	# Should NOT produce any deny results (task is trusted via legacy)
	lib.assert_empty(trusted_task.deny) with input.attestations as [att]
		with data.trusted_tasks as rules_trusted_tasks_data
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
}

# A2 — On trusted_tasks, but expired → untrusted
# Task is in trusted_tasks with expired date → should produce deny
test_on_trusted_tasks_expired_untrusted if {
	rules_trusted_tasks_data := {"oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4": [{
		"ref": "sha256:abc123",
		"expires_on": "2024-12-31T00:00:00Z",
	}]}

	trusted_task_rules_data := {
		"allow": [],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	expected := {{
		"code": "trusted_task.trusted",
		# regal ignore:line-length
		"msg": `PipelineTask "buildah-task" uses an untrusted task reference: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123`,
		"term": "task-buildah",
	}}

	# Should produce deny result (task expired in trusted_tasks, no upgrade path available)
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as rules_trusted_tasks_data
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-01-10T00:00:00Z")
}

# A3 — Not on trusted_tasks, no rules → missing data error
# Task is not in trusted_tasks, no rules → should produce deny for missing data
test_not_on_trusted_tasks_no_rules_untrusted if {
	rules_trusted_tasks_data := {}

	trusted_task_rules_data := {
		"allow": [],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"other-task",
		"quay.io/myorg/other/task:1.0@sha256:abc123",
		"other-task",
	)])

	expected := {{
		"code": "trusted_task.data",
		"msg": "Missing required trusted_tasks data",
	}}

	# When both trusted_tasks and trusted_task_rules are empty, should produce data error
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as rules_trusted_tasks_data
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
}

#####################################################
# 2. Basic Allow Rules (B1-B2)
#####################################################

# B1 — Allow by location
# Task matches allow pattern → should NOT produce warn
test_allow_by_location if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Trust all tekton-catalog",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	# Should NOT produce any deny results (task allowed by rules)
	# With trusted_task_rules provided, uses deny rule (trusted_rules)
	lib.assert_empty(trusted_task.deny) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
}

# B2 — Outside pattern → not trusted
# Task does NOT match allow pattern → should produce warn
test_outside_pattern_not_trusted if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Trust all tekton-catalog",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"other-task",
		"quay.io/myorg/other/task:1.0@sha256:abc123",
		"other-task",
	)])

	expected := {{
		"code": "trusted_task.trusted",
		# regal ignore:line-length
		"msg": `PipelineTask "other-task" uses an untrusted task reference: oci://quay.io/myorg/other/task:1.0@sha256:abc123. The denial reason is: not_allowed`,
		"term": "other-task",
	}}

	# Should produce deny result (task outside allow pattern)
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
}

#####################################################
# 3. Deny Precedence (C1-C2)
#####################################################

# Deny rules take precedence over allow rules
# Task matches allow pattern but also matches deny → should produce deny with message
test_deny_takes_precedence_over_allow if {
	task_rules := {
		"allow": [{
			"name": "Allow tekton catalog",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [{
			"name": "Block buildah 0.4",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
			"message": "task-buildah:0.4 is deprecated",
			"effective_on": "2025-01-01",
		}],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	expected := {{
		"code": "trusted_task.trusted",
		# regal ignore:line-length
		"msg": "PipelineTask \"buildah-task\" uses an untrusted task reference: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123. The denial reason is: deny_rule\n  - oci://quay.io/konflux-ci/tekton-catalog/task-buildah*\nMessages:\n  - task-buildah:0.4 is deprecated",
		"term": "task-buildah",
	}}

	# Should produce deny result (deny rule takes precedence over allow)
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as task_rules
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-01-10T00:00:00Z")
}

#####################################################
# 4. Time-Based Allow Rules (D1)
#####################################################

# D1 — Allow rule not yet effective → not trusted
test_allow_rule_not_yet_effective if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Trust tekton starting Feb",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			"effective_on": "2025-02-01",
		}],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	expected := {{
		"code": "trusted_task.trusted",
		# regal ignore:line-length
		"msg": `PipelineTask "buildah-task" uses an untrusted task reference: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123. The denial reason is: no_effective_rules`,
		"term": "task-buildah",
	}}

	# Before effective date - should produce deny (rule not yet effective)
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-01-15T00:00:00Z")
}

# D1 — Allow rule becomes effective → trusted
test_allow_rule_effective_trusted if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Trust tekton starting Feb",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			"effective_on": "2025-02-01",
		}],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	# After effective date - should NOT produce deny (rule is now effective)
	# With trusted_task_rules provided, uses deny rule (trusted_rules)
	lib.assert_empty(trusted_task.deny) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-02-10T00:00:00Z")
}

# Time-based deny rule - not yet effective
test_deny_rule_not_yet_effective if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Allow tekton catalog",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [{
			"name": "Expire buildah",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
			"effective_on": "2025-03-01",
		}],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	# Before deny effective date - should NOT produce deny result (deny rule not yet effective)
	# With trusted_task_rules provided, uses deny rule (trusted_rules)
	lib.assert_empty(trusted_task.deny) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-02-15T00:00:00Z")
}

# Time-based deny rule - becomes effective
test_deny_rule_becomes_effective if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Allow tekton catalog",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [{
			"name": "Expire buildah",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
			"effective_on": "2025-03-01",
		}],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	expected := {{
		"code": "trusted_task.trusted",
		# regal ignore:line-length
		"msg": "PipelineTask \"buildah-task\" uses an untrusted task reference: oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123. The denial reason is: deny_rule\n  - oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
		"term": "task-buildah",
	}}

	# After deny effective date - should produce deny result
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-03-15T00:00:00Z")
}

#####################################################
# 6. Overlapping Allow Rules (F1)
#####################################################

# Multiple allow rules with same pattern - task matching any effective rule is trusted
test_multiple_allow_rules if {
	trusted_task_rules_data := {
		"allow": [
			{
				"name": "Base allow by location",
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			},
			{
				"name": "Additional allow rule with different scope",
				"pattern": "oci://quay.io/konflux-ci/*",
			},
		],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	# Task matches both allow rules - should be trusted
	# With trusted_task_rules provided, uses deny rule (trusted_rules)
	lib.assert_empty(trusted_task.deny) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
}

#####################################################
# 7. Deprecation Deny Rule With Message (G1)
#####################################################

# G1 — Deny with user-visible message
test_deny_with_message if {
	task_rules := {
		"allow": [{
			"name": "Allow tekton",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [{
			"name": "Deprecate manifest",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-build-image-manifest*",
			"message": "This task was renamed to build-image-index.",
			"effective_on": "2025-10-26",
		}],
	}

	att := _rules_make_attestation([_rules_make_task(
		"manifest-task",
		"quay.io/konflux-ci/tekton-catalog/task-build-image-manifest:1.0@sha256:abc123",
		"task-build-image-manifest",
	)])

	expected := {{
		"code": "trusted_task.trusted",
		# regal ignore:line-length
		"msg": "PipelineTask \"manifest-task\" uses an untrusted task reference: oci://quay.io/konflux-ci/tekton-catalog/task-build-image-manifest:1.0@sha256:abc123. The denial reason is: deny_rule\n  - oci://quay.io/konflux-ci/tekton-catalog/task-build-image-manifest*\nMessages:\n  - This task was renamed to build-image-index.",
		"term": "task-build-image-manifest",
	}}

	# Should produce deny result with message
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as task_rules
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-11-01T00:00:00Z")
}

#####################################################
# 8. Rules Take Precedence Over trusted_tasks (H1)
#####################################################

# H1 — Rules allow, trusted_tasks expiry is ignored
# When allow rules ARE defined and match, the task is trusted via rules
# regardless of legacy expiry
test_rules_allow_trusted_tasks_expiry_ignored if {
	rules_trusted_tasks_data := {"oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4": [{
		"ref": "sha256:abc123",
		"expires_on": "2025-01-01T00:00:00Z",
	}]}

	trusted_task_rules_data := {
		"allow": [{
			"name": "Allow tekton catalog",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	# Should NOT produce deny (allow rule matches, trusted_tasks expiry is ignored)
	# With trusted_task_rules provided, uses deny rule (trusted_rules)
	lib.assert_empty(trusted_task.deny) with input.attestations as [att]
		with data.trusted_tasks as rules_trusted_tasks_data
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2025-02-01T00:00:00Z")
}

#####################################################
# 11. Unknown Fields Ignored (K1)
#####################################################

# K1 — Unknown fields ignored
test_unknown_fields_ignored if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Allow tekton",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			"foo": "bar", # unknown field - should be ignored
		}],
		"deny": [],
	}

	att := _rules_make_attestation([_rules_make_task(
		"buildah-task",
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
		"task-buildah",
	)])

	# Should NOT produce any deny results (unknown field is ignored)
	# Unknown fields should be ignored per the JSON schema's additionalProperties: true
	# With trusted_task_rules provided, uses deny rule (trusted_rules)
	lib.assert_empty(trusted_task.deny) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
}

#####################################################
# Additional edge case tests
#####################################################

# Test multiple tasks - some trusted, some not
test_mixed_trusted_and_untrusted_tasks if {
	trusted_task_rules_data := {
		"allow": [{
			"name": "Allow tekton catalog",
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
		}],
		"deny": [],
	}

	att := _rules_make_attestation([
		_rules_make_task(
			"trusted-task",
			"quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abc123",
			"task-buildah",
		),
		_rules_make_task(
			"untrusted-task",
			"quay.io/evil/malicious-task:1.0@sha256:evil123",
			"malicious-task",
		),
	])

	expected := {{
		"code": "trusted_task.trusted",
		# regal ignore:line-length
		"msg": `PipelineTask "untrusted-task" uses an untrusted task reference: oci://quay.io/evil/malicious-task:1.0@sha256:evil123. The denial reason is: not_allowed`,
		"term": "malicious-task",
	}}

	# Should produce deny for the untrusted task only
	lib.assert_equal_results(trusted_task.deny, expected) with input.attestations as [att]
		with data.trusted_tasks as {}
		with data.rule_data.trusted_task_rules as trusted_task_rules_data
}

test_signature_verification_failed_error_rules if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [trusted_bundle_pipeline_task]},
		},
	}}

	rules := {"allow": [{
		"name": "signed catalog",
		"pattern": "oci://registry.local/trusty*",
		"signature_verification": {
			"certificate_identity_regexp": "https://tekton.dev/chains/.*",
			"certificate_oidc_issuer": "https://accounts.google.com",
		},
	}]}

	results := trusted_task.deny with input.attestations as [att]
		with data.trusted_task_rules as rules
		with ec.sigstore.verify_image as _mock_verify_image_failure

	count(results) > 0
	some result in results
	contains(result.msg, "signature_verification_failed")
}

_mock_verify_image_failure(_, _) := {"success": false, "errors": ["signature verification failed"]}

#####################################################
# Helper Functions for trusted_task_rules tests
#####################################################

# Create a simple attestation structure for testing
_rules_make_attestation(tasks) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": tasks},
	},
}}

# Create a bundle task reference for testing
# Uses the SLSA v0.2 format that lib.tasks_from_pipelinerun expects
_rules_make_task(pipeline_task_name, bundle, task_name) := {
	"name": pipeline_task_name,
	"ref": {"resolver": "bundles", "params": [
		{"name": "bundle", "value": bundle},
		{"name": "name", "value": task_name},
		{"name": "kind", "value": "task"},
	]},
}
