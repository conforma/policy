package task_bundle_test

import rego.v1

import data.lib.assertions

import data.task_bundle

test_bundle_not_exists if {
	tasks := [{"name": "my-task", "taskRef": {}}]

	expected_msg := "Pipeline task 'my-task' does not contain a bundle reference"
	assertions.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.disallowed_task_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data.trusted_tasks as trusted_tasks

	assertions.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
}

test_bundle_not_exists_empty_string if {
	tasks := [{"name": "my-task", "taskRef": {"bundle": ""}}]

	expected_msg := "Pipeline task 'my-task' uses an empty bundle image reference"
	assertions.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.empty_task_bundle_reference",
		"msg": expected_msg,
	}}) with input.spec.tasks as tasks with data.trusted_tasks as trusted_tasks

	assertions.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
}

test_bundle_unpinned if {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "reg.com/repo:latest"},
	}]

	assertions.assert_equal_results(task_bundle.warn, {{
		"code": "task_bundle.unpinned_task_bundle",
		"msg": "Pipeline task 'my-task' uses an unpinned task bundle reference 'reg.com/repo:latest'",
	}}) with input.spec.tasks as tasks with data.trusted_tasks as {}
}

test_bundle_reference_valid if {
	tasks := [{
		"name": "my-task",
		"taskRef": {"bundle": "reg.com/repo:v2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
	}]

	assertions.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest
	assertions.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest
}

# All good when the most recent bundle is used.
test_trusted_bundle_up_to_date if {
	# regal ignore:line-length
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo:v2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"}}]

	assertions.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest

	assertions.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest
}

# All good when the most recent bundle is used for a version that is still maintained
test_trusted_bundle_up_to_date_maintained_version if {
	# regal ignore:line-length
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo:v3@sha256:0000000000000000000000000000000000000000000000000000000000000901"}}]

	assertions.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest

	assertions.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest
}

# Warn about out of date bundles that are still trusted.
test_trusted_bundle_out_of_date_past if {
	# regal ignore:line-length
	tasks := [{"name": "my-task-1", "taskRef": {"bundle": "reg.com/repo:v2@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd"}}]

	assertions.assert_equal_results(task_bundle.warn, {{
		"code": "task_bundle.out_of_date_task_bundle",
		# regal ignore:line-length
		"msg": "Pipeline task 'my-task-1' uses an out of date task bundle 'reg.com/repo:v2@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd', new version of the Task must be used before 2022-04-11T00:00:00Z",
	}}) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest

	assertions.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2022-03-12T00:00:00Z")
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest
}

# Deny bundles that are no longer active.
test_trusted_bundle_expired if {
	# regal ignore:line-length
	tasks := [{"name": "my-task", "taskRef": {"bundle": "reg.com/repo@sha256:def0000000000000000000000000000000000000000000000000000000000def"}}]

	assertions.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest

	assertions.assert_equal_results(task_bundle.deny, {{
		"code": "task_bundle.untrusted_task_bundle",
		# regal ignore:line-length
		"msg": "Pipeline task 'my-task' uses an untrusted task bundle 'reg.com/repo@sha256:def0000000000000000000000000000000000000000000000000000000000def'",
	}}) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest
}

test_ec316 if {
	tasks := [{
		"name": "my-task",
		# regal ignore:line-length
		"taskRef": {"bundle": "registry.io/repository/image:0.3@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
	}]

	trusted_tasks := {
		# regal ignore:line-length
		"oci://registry.io/repository/image:0.1": [{"ref": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc", "effective_on": "2024-02-02T00:00:00Z"}],
		# regal ignore:line-length
		"oci://registry.io/repository/image:0.2": [{"ref": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc", "effective_on": "2024-02-02T00:00:00Z"}],
		"oci://registry.io/repository/image:0.3": [
			# regal ignore:line-length
			{"ref": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc", "effective_on": "2024-02-02T00:00:00Z"},
			# regal ignore:line-length
			{"ref": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc", "effective_on": "2024-01-21T00:00:00Z"},
			# regal ignore:line-length
			{"ref": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc", "effective_on": "2024-01-21T00:00:00Z"},
		],
	}

	assertions.assert_empty(task_bundle.warn) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest

	assertions.assert_empty(task_bundle.deny) with input.spec.tasks as tasks
		with data.trusted_tasks as trusted_tasks
		with ec.oci.image_manifests as _mock_image_manifests
		with ec.oci.image_manifest as _mock_image_manifest
}

test_missing_required_data if {
	expected := {{
		"code": "task_bundle.missing_required_data",
		"msg": "Missing required trusted_tasks data",
	}}
	assertions.assert_equal_results(expected, task_bundle.deny) with data.trusted_tasks as {}
}

trusted_tasks := {
	# regal ignore:line-length
	"oci://reg.com/repo:v3": [{"ref": "sha256:0000000000000000000000000000000000000000000000000000000000000901", "effective_on": "2022-04-11T00:00:00Z"}],
	"oci://reg.com/repo:v2": [
		# Latest v2
		# regal ignore:line-length
		{"ref": "sha256:abc0000000000000000000000000000000000000000000000000000000000abc", "effective_on": "2022-04-11T00:00:00Z"},
		# Older v2
		# regal ignore:line-length
		{"ref": "sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd", "effective_on": "2022-03-11T00:00:00Z", "expires_on": "2022-04-11T00:00:00Z"},
	],
	"oci://reg.com/repo:v1": [
		# Latest v1
		# regal ignore:line-length
		{"ref": "sha256:cde0000000000000000000000000000000000000000000000000000000000cde", "effective_on": "2022-02-01T00:00:00Z"},
		# Older v1
		# regal ignore:line-length
		{"ref": "sha256:def0000000000000000000000000000000000000000000000000000000000def", "effective_on": "2021-01-01T00:00:00Z", "expires_on": "2022-02-01T00:00:00Z"},
	],
}

# Mock function for ec.oci.image_manifests
_mock_image_manifests(refs) := {ref: {} | some ref in refs}

# Mock function for ec.oci.image_manifest (singular)
_mock_image_manifest(_) := {}

test_mock_image_manifest if {
	result := _mock_image_manifest("any-ref")
	assertions.assert_equal({}, result)
}

# G43 / RA03-BUNDLE-DIGEST-SHAPE-001: an allow pattern must not hide
# the advisory when only the bundle's digest suffix becomes malformed.
test_bundle_malformed_digest_warning if {
	every ref in ["registry.local/task:1.0", "registry.local/task:1.0@not-a-digest", "registry.local/task:1.0@sha256:"] {
		task := {"name": "task", "taskRef": {"bundle": ref}}
		results := task_bundle.warn with input.spec.tasks as [task]
			with ec.oci.image_manifests as {}
			with data.rule_data.trusted_task_rules_enabled as true
			with data.rule_data.trusted_task_rules as {"allow": {"test": [{"pattern": "oci://registry.local/task*"}]}, "deny": {}}
		assertions.assert_equal({r.code | some r in results}, {"task_bundle.unpinned_task_bundle"})
		assertions.assert_empty(task_bundle.deny) with input.spec.tasks as [task]
			with ec.oci.image_manifests as {}
			with data.rule_data.trusted_task_rules_enabled as true
			with data.rule_data.trusted_task_rules as {"allow": {"test": [{"pattern": "oci://registry.local/task*"}]}, "deny": {}}
	}
}
