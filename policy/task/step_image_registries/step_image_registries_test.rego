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
	}

	assertions.assert_equal_results(expected, step_image_registries.deny) with data.rule_data as d
}
