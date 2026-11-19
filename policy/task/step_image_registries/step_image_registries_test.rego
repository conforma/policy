package step_image_registries_test

import rego.v1

import data.lib.assertions

import data.step_image_registries

# regal ignore:line-length
good_image := "registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b"

# regal ignore:line-length
bad_image := "hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b"

test_step_images_permitted_success if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"spec": {"steps": [{"image": good_image}, {"image": good_image}]},
	}

	assertions.assert_empty(step_image_registries.deny) with input as task
}

test_step_images_permitted_failure if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}, "name": "git-clone"},
		"spec": {"steps": [{"image": bad_image}, {"image": good_image}, {"image": bad_image}]},
	}

	expected := {
		{
			"code": "step_image_registries.step_images_permitted",
			# regal ignore:line-length
			"msg": "Step 0 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
			"term": "git-clone/1.0",
		},
		{
			"code": "step_image_registries.step_images_permitted",
			# regal ignore:line-length
			"msg": "Step 2 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
			"term": "git-clone/1.0",
		},
	}

	assertions.assert_equal_results(step_image_registries.deny, expected) with input as task
}

test_step_images_missing_name_version if {
	task_no_name := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}},
		"spec": {"steps": [{"image": bad_image}]},
	}

	assertions.assert_equal_results(step_image_registries.deny, {{
		"code": "step_image_registries.step_images_permitted",
		# regal ignore:line-length
		"msg": "Step 0 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
		"term": "noname/1.0",
	}}) with input as task_no_name

	task_no_version := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"metadata": {"name": "git-clone"},
		"spec": {"steps": [{"image": bad_image}]},
	}

	assertions.assert_equal_results(step_image_registries.deny, {{
		"code": "step_image_registries.step_images_permitted",
		# regal ignore:line-length
		"msg": "Step 0 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
		"term": "git-clone/noversion",
	}}) with input as task_no_version

	task_no_name_no_version := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"spec": {"steps": [{"image": bad_image}]},
	}

	assertions.assert_equal_results(step_image_registries.deny, {{
		"code": "step_image_registries.step_images_permitted",
		# regal ignore:line-length
		"msg": "Step 0 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
		"term": "noname/noversion",
	}}) with input as task_no_name_no_version
}

test_step_images_permitted_skipped if {
	not_a_task := {
		"kind": "Taskinha",
		"spec": {"steps": [{"image": bad_image}]},
	}

	assertions.assert_empty(step_image_registries.deny) with input as not_a_task
}

test_step_images_permitted_prefix_list_empty if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}, "name": "git-clone"},
		"spec": {"steps": [{"image": good_image}]},
	}

	expected := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_images_permitted",
			# regal ignore:line-length
			"msg": "Step 0 uses disallowed image ref 'registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
			"term": "git-clone/1.0",
		},
	}

	assertions.assert_equal_results(step_image_registries.deny, expected) with input as task
		with data.rule_data as {}
}

test_step_image_registry_prefix_list_format if {
	d := {"allowed_step_image_registry_prefixes": [
		# Wrong type
		1,
		# Duplicated items
		"registry.local/",
		"registry.local/",
	]}

	expected := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(expected, step_image_registries.deny) with data.rule_data as d
}

# A present but scalar `allowed_step_image_registry_prefixes` value must produce a
# format rejection from the v2 rule instead of silently skipping the check. The
# legacy step_image_registry_prefix_list_provided is untouched: a builtin error in
# its schema validation still suppresses its result, which is the gap the v2 rule
# closes. The step-images consumer is independently fail-closed under scalar data
# (it denies every step), so the isolated assertion below uses a Task without
# steps to show that only the v2 rule fires; the assertion with a real step locks
# in that existing consumer behavior.
test_step_image_registry_prefix_list_provided_v2_scalar_rejected if {
	task_without_steps := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"spec": {"steps": []},
	}

	expected_int := {{
		"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(step_image_registries.deny, expected_int) with input as task_without_steps
		with data.rule_data as {"allowed_step_image_registry_prefixes": 1}

	expected_str := {{
		"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(step_image_registries.deny, expected_str) with input as task_without_steps
		with data.rule_data as {"allowed_step_image_registry_prefixes": "x"}

	expected_bool := {{
		"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: boolean",
		"severity": "failure",
	}}
	assertions.assert_equal_results(step_image_registries.deny, expected_bool) with input as task_without_steps
		with data.rule_data as {"allowed_step_image_registry_prefixes": true}

	task_with_step := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}, "name": "git-clone"},
		"spec": {"steps": [{"image": good_image}]},
	}

	expected_with_step := expected_int | {{
		"code": "step_image_registries.step_images_permitted",
		# regal ignore:line-length
		"msg": "Step 0 uses disallowed image ref 'registry.redhat.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
		"term": "git-clone/1.0",
	}}
	assertions.assert_equal_results(step_image_registries.deny, expected_with_step) with input as task_with_step
		with data.rule_data as {"allowed_step_image_registry_prefixes": 1}
}

# A string value is malformed even when it contains JSON text for a valid array:
# the legacy rule parses the JSON text and reports the empty-array violation,
# while the v2 rule rejects the string itself. A native empty array stays invalid
# for this key on both rules.
test_step_image_registry_prefix_list_provided_v2_json_text_string_rejected if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"spec": {"steps": []},
	}

	expected_json_text := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(step_image_registries.deny, expected_json_text) with input as task
		with data.rule_data as {"allowed_step_image_registry_prefixes": "[]"}

	expected_native_empty := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(step_image_registries.deny, expected_native_empty) with input as task
		with data.rule_data as {"allowed_step_image_registry_prefixes": []}
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_step_image_registry_prefix_list_provided_v2_precedence if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"spec": {"steps": []},
	}

	expected := {{
		"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}

	assertions.assert_equal_results(step_image_registries.deny, expected) with input as task
		with data.rule_data_custom as {"allowed_step_image_registry_prefixes": 1}
		with data.rule_data as {"allowed_step_image_registry_prefixes": ["registry.redhat.io/"]}
}

# Valid rule data still reaches the step-images consumer: a step image from an
# allowed registry prefix passes, and one from a disallowed prefix is still
# denied by the consumer rule without any format result.
test_step_images_permitted_with_valid_prefix_list if {
	task_good := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}, "name": "git-clone"},
		"spec": {"steps": [{"image": good_image}]},
	}

	d := {"allowed_step_image_registry_prefixes": ["registry.redhat.io/"]}

	assertions.assert_empty(step_image_registries.deny) with input as task_good
		with data.rule_data as d

	task_bad := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"metadata": {"labels": {"app.kubernetes.io/version": "1.0"}, "name": "git-clone"},
		"spec": {"steps": [{"image": bad_image}]},
	}

	expected := {{
		"code": "step_image_registries.step_images_permitted",
		# regal ignore:line-length
		"msg": "Step 0 uses disallowed image ref 'hackz.io/openshift-pipelines/pipelines-git-init-rhel8@sha256:af7dd5b3b0000000000000000000000000000000000000000000000af7dd5b3b'",
		"term": "git-clone/1.0",
	}}

	assertions.assert_equal_results(step_image_registries.deny, expected) with input as task_bad
		with data.rule_data as d
}

# Shape controls locking in the current behavior of both format rules for a null
# value and a wrong-container value.
test_step_image_registry_prefix_list_shape_controls if {
	task := {
		"apiVersion": "tekton.dev/v1", "kind": "Task",
		"spec": {"steps": []},
	}

	expected_null := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(step_image_registries.deny, expected_null) with input as task
		with data.rule_data as {"allowed_step_image_registry_prefixes": null}

	expected_object := {
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
		{
			"code": "step_image_registries.step_image_registry_prefix_list_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(step_image_registries.deny, expected_object) with input as task
		with data.rule_data as {"allowed_step_image_registry_prefixes": {"registry.local/": true}}
}
