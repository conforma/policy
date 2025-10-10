package trusted_tasks_simplified

import rego.v1

import data.lib

test_missing_trusted_tasks_data if {
	lib.assert_equal(true, _missing_trusted_tasks_data)
}

test_missing_trusted_tasks_data_with_data if {
	lib.assert_equal(false, _missing_trusted_tasks_data) with data.trusted_tasks as {"test": []}
}

testuntrusted_task_refs if {
	tasks := [
		{
			"name": "build",
			"ref": {
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.5",
				"kind": "Task",
			},
		},
		{
			"name": "test",
			"ref": {
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-test:0.1",
				"kind": "Task",
			},
		},
	]

	expected := [
		{
			"name": "test",
			"ref": {
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-test:0.1",
				"kind": "Task",
			},
		},
	]

	lib.assert_equal(expected, untrusted_task_refs(tasks)) with data.trusted_tasks as {"test": []}
}

testis_trusted_task_trusted_bundle_task if {
	trusted_bundle_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.5@sha256:1234567890abcdef",
			"kind": "Task",
		},
	}

	is_trusted_task(trusted_bundle_task) with data.trusted_tasks as {"test": []}
}

testis_trusted_task_trusted_git_task if {
	trusted_git_task := {
		"name": "build",
		"ref": {
			"resolver": "git",
			"url": "https://github.com/konflux-ci/build-definitions.git",
			"revision": "51ab22f576864d90b5ad3e459e2eb3da416c07ba",
			"pathInRepo": "task/acs-deploy-check/0.1/acs-deploy-check.yaml",
			"kind": "Task",
		},
	}

	is_trusted_task(trusted_git_task) with data.trusted_tasks as {"test": []}
}

testis_trusted_task_untrusted_bundle_task if {
	untrusted_bundle_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:abcdef1234567890",
			"kind": "Task",
		},
	}

	not is_trusted_task(untrusted_bundle_task) with data.trusted_tasks as {"test": []}
}

testis_trusted_task_untrusted_git_task if {
	untrusted_git_task := {
		"name": "build",
		"ref": {
			"resolver": "git",
			"url": "https://github.com/konflux-ci/build-definitions.git",
			"revision": "invalid-commit",
			"pathInRepo": "task/acs-deploy-check/0.1/acs-deploy-check.yaml",
			"kind": "Task",
		},
	}

	not is_trusted_task(untrusted_git_task) with data.trusted_tasks as {"test": []}
}

testis_trusted_task_expired_trusted_git_task if {
	expired_trusted_git_task := {
		"name": "build",
		"ref": {
			"resolver": "git",
			"url": "https://github.com/konflux-ci/build-definitions.git",
			"revision": "2b07ac561f8e79d8103fffb62859af60ad3a358f",
			"pathInRepo": "task/acs-deploy-check/0.1/acs-deploy-check.yaml",
			"kind": "Task",
		},
	}

	not is_trusted_task(expired_trusted_git_task) with data.trusted_tasks as {"test": []}
}

testis_trusted_task_expired_trusted_bundle_task if {
	expired_trusted_bundle_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:7aef142f50fe1352329f6fc9ca4bd85fa32d5658",
			"kind": "Task",
		},
	}

	not is_trusted_task(expired_trusted_bundle_task) with data.trusted_tasks as {"test": []}
}

# Test simplified format rule-based trust
testis_trusted_task_simplified_allowed_oci if {
	allowed_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.6@sha256:newhash",
			"kind": "Task",
		},
	}

	is_trusted_task(allowed_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "oci://quay.io/konflux-ci/tekton-catalog/*",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
	}
}

testis_trusted_task_simplified_allowed_git if {
	allowed_task := {
		"name": "build",
		"ref": {
			"resolver": "git",
			"url": "https://github.com/konflux-ci/build-definitions.git",
			"revision": "newcommit",
			"pathInRepo": "task/acs-deploy-check/0.1/acs-deploy-check.yaml",
			"kind": "Task",
		},
	}

	is_trusted_task(allowed_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "git+https://github.com/konflux-ci/build-definitions.git//*",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
	}
}

testis_trusted_task_simplified_denied if {
	denied_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.3@sha256:oldhash",
			"kind": "Task",
		},
	}

	not is_trusted_task(denied_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "oci://quay.io/konflux-ci/tekton-catalog/*",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
		"denied_tasks": [
			{
				"task": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.3",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
	}
}

testis_trusted_task_simplified_future_effective if {
	future_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.7@sha256:futurehash",
			"kind": "Task",
		},
	}

	not is_trusted_task(future_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "oci://quay.io/konflux-ci/tekton-catalog/*",
				"effective_on": "2025-01-01T00:00:00Z",
			},
		],
	}
}

testis_trusted_task_simplified_version_constraints if {
	versioned_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.5@sha256:versionedhash",
			"kind": "Task",
		},
	}

	is_trusted_task(versioned_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah:>=0.5",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
	}
}

testis_trusted_task_simplified_version_constraints_denied if {
	versioned_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.3@sha256:versionedhash",
			"kind": "Task",
		},
	}

	not is_trusted_task(versioned_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah:>=0.5",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
	}
}

testis_trusted_task_simplified_signing_required if {
	signed_task := {
		"name": "build",
		"ref": {
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.8@sha256:signedhash",
			"kind": "Task",
		},
	}

	is_trusted_task(signed_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah:*",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
		"signing_required": {
			"patterns": ["oci://quay.io/konflux-ci/tekton-catalog/*"],
			"effective_on": "2026-01-01T00:00:00Z",
			"signing_key": "expected-key",
		},
	}
}

testis_trusted_task_simplified_specific_task_path if {
	specific_task := {
		"name": "build",
		"ref": {
			"resolver": "git",
			"url": "https://github.com/konflux-ci/build-definitions.git",
			"revision": "specificcommit",
			"pathInRepo": "task/acs-deploy-check/0.1/acs-deploy-check.yaml",
			"kind": "Task",
		},
	}

	is_trusted_task(specific_task) with data.trusted_task_rules as {
		"allowed_tasks": [
			{
				"task": "git+https://github.com/konflux-ci/build-definitions.git//task/acs-deploy-check/0.1/acs-deploy-check.yaml",
				"effective_on": "2024-01-01T00:00:00Z",
			},
		],
	}
}
