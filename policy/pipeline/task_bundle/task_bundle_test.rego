package task_bundle_test

import rego.v1

import data.lib.utils as lib
import data.task_bundle

test_bundle_not_exists if {
	tasks := [{"name": "my-task", "taskRef": {}}]

	expected_msg := "Pipeline task 'my-task' does not contain a bundle reference"
	lib.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.disallowed_task_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data.trusted_tasks as trusted_tasks

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
}

test_bundle_not_exists_empty_string if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": ""}}]

	expected_msg := "Pipeline task 'my-task' uses an empty bundle image reference"
	lib.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.empty_task_bundle_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data.trusted_tasks as trusted_tasks

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
}

test_bundle_unpinned if {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "reg.com/repo:latest"},
	}]

	lib.assert_equal_results(task_bundle.warn, {{
		"code": "task_bundle.unpinned_task_bundle",
		"msg": "Pipeline task 'my-task' uses an unpinned task bundle reference 'reg.com/repo:latest'",
	}}) with input.spec.tasks as tasks with data.trusted_tasks as {}
}

test_bundle_reference_valid if {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "reg.com/repo:v2@sha256:abc"},
	}]

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks with data.trusted_tasks as trusted_tasks
	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks with data.trusted_tasks as trusted_tasks
}

# All good when the most recent bundle is used.
test_trusted_bundle_up_to_date if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo:v2@sha256:abc"}}]

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
}

# All good when the most recent bundle is used for a version that is still maintained
test_trusted_bundle_up_to_date_maintained_version if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo:v3@sha256:ghi"}}]

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
}

# Warn about out of date bundles that are still trusted.
test_trusted_bundle_out_of_date_past if {
	tasks := [{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo:v2@sha256:bcd"}}]

	lib.assert_equal_results(task_bundle.warn, {{
		"code": "task_bundle.out_of_date_task_bundle",
		# regal ignore:line-length
		"msg": "Pipeline task 'my-task-1' uses an out of date task bundle 'reg.com/repo:v2@sha256:bcd', new version of the Task must be used before 2022-04-11T00:00:00Z",
	}}) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")
}

# Deny bundles that are no longer active.
test_trusted_bundle_expired if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo@sha256:def"}}]

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks

	lib.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.untrusted_task_bundle",
		"msg": "Pipeline task 'my-task' uses an untrusted task bundle 'reg.com/repo@sha256:def'",
	}}) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
}

test_ec316 if {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "registry.io/repository/image:0.3@sha256:abc"},
	}]

	trusted_tasks := {
		"oci://registry.io/repository/image:0.1": [{"ref": "sha256:abc", "effective_on": "2024-02-02T00:00:00Z"}],
		"oci://registry.io/repository/image:0.2": [{"ref": "sha256:abc", "effective_on": "2024-02-02T00:00:00Z"}],
		"oci://registry.io/repository/image:0.3": [
			{"ref": "sha256:abc", "effective_on": "2024-02-02T00:00:00Z"},
			{"ref": "sha256:abc", "effective_on": "2024-01-21T00:00:00Z"},
			{"ref": "sha256:abc", "effective_on": "2024-01-21T00:00:00Z"},
		],
	}

	lib.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks

	lib.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
}

test_missing_required_data if {
	expected := {{
		"code": "task_bundle.missing_required_data",
		"msg": "Missing required trusted_tasks data",
	}}
	lib.assert_equal_results(expected, task_bundle.deny) with data.trusted_tasks as {}
}

trusted_tasks := {
	"oci://reg.com/repo:v3": [{"ref": "sha256:ghi", "effective_on": "2022-04-11T00:00:00Z"}],
	"oci://reg.com/repo:v2": [
		# Latest v2
		{"ref": "sha256:abc", "effective_on": "2022-04-11T00:00:00Z"},
		# Older v2
		{"ref": "sha256:bcd", "effective_on": "2022-03-11T00:00:00Z", "expires_on": "2022-04-11T00:00:00Z"},
	],
	"oci://reg.com/repo:v1": [
		# Latest v1
		{"ref": "sha256:cde", "effective_on": "2022-02-01T00:00:00Z"},
		# Older v1
		{"ref": "sha256:def", "effective_on": "2021-01-01T00:00:00Z", "expires_on": "2022-02-01T00:00:00Z"},
	],
}
