package lib.tekton_test

import rego.v1

import data.lib.assertions
import data.lib.tekton
import data.lib.time as time_lib

# #############################################################################
# TRUSTED TASK LIBRARY TESTS
# #############################################################################
#
# Test organization:
# - SHARED HELPERS: Tests for functions used by both systems
# - ROUTING LAYER: Tests for is_trusted_task and untrusted_task_refs
# - RULES SYSTEM: Tests for trusted_task_rules functionality
# - LEGACY SYSTEM: Tests for trusted_tasks functionality (DELETE when removing legacy)
#
# Test data:
# - trusted_tasks (at bottom): LEGACY test data - DELETE when removing legacy
# - trusted_task_rules_* variables: RULES test data - keep
#
# #############################################################################

# Helper to create a mock bundle_manifests map for testing
# bundle_ref: the bundle reference (e.g., "registry.local/trusty:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700")
# version: the version annotation value (e.g., "1.0")
# regal ignore:line-length
_mock_bundle_manifests(bundle_ref, version) := {bundle_ref: {"annotations": {"org.opencontainers.image.version": version}}}

# Empty bundle_manifests for tests that don't need version checking
_empty_bundle_manifests := {}

# =============================================================================
# SHARED HELPERS TESTS
# =============================================================================

test_unpinned_task_references if {
	tasks := [
		trusted_bundle_task,
		unpinned_bundle_task,
		trusted_git_task,
		unpinned_git_task,
	]

	expected := {unpinned_bundle_task, unpinned_git_task}

	assertions.assert_equal(expected, tekton.unpinned_task_references(tasks)) with data.trusted_tasks as trusted_tasks
}

# =============================================================================
# BEGIN LEGACY SYSTEM TESTS (trusted_tasks)
# DELETE THIS SECTION when removing legacy support.
# =============================================================================

test_missing_trusted_tasks_data if {
	assertions.assert_equal(true, tekton.missing_trusted_tasks_data)

	assertions.assert_equal(false, tekton.missing_trusted_tasks_data) with data.trusted_tasks as trusted_tasks
}

test_task_expiry_warnings_after if {
	# default
	assertions.assert_equal(0, tekton.task_expiry_warnings_after)

	# with rule data
	assertions.assert_equal(
		time.add_date(
			time_lib.effective_current_time_ns, 0, 0,
			16,
		),
		tekton.task_expiry_warnings_after,
	) with data.rule_data.task_expiry_warning_days as 16
}

test_expiry_of if {
	# defaults
	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(same_date_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks

	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks

	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_git_task))) with data.trusted_tasks as trusted_tasks

	# when running far in the future without the grace period
	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(same_date_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")

	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")

	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_git_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")

	# when running far in the future within the grace period
	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(same_date_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6

	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_bundle_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6

	# regal ignore:line-length
	assertions.assert_equal("2099-01-01T00:00:00Z", time.format(tekton.expiry_of(outdated_trusted_git_task))) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 6

	# when running far in the future outside the grace period
	not tekton.expiry_of(same_date_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(newest_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(outdated_trusted_bundle_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(newest_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
	not tekton.expiry_of(outdated_trusted_git_task) with data.trusted_tasks as trusted_tasks
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2098-12-25T00:00:00Z")
		with data.rule_data.task_expiry_warning_days as 7
}

# =============================================================================
# ROUTING LAYER TESTS
# Tests for unified functions that route to appropriate system.
# =============================================================================

test_untrusted_task_refs if {
	tasks := [
		trusted_bundle_task,
		untrusted_bundle_task,
		expired_trusted_bundle_task,
		trusted_git_task,
		untrusted_git_task,
		expired_trusted_git_task,
	]

	expected := {untrusted_bundle_task, expired_trusted_bundle_task, untrusted_git_task, expired_trusted_git_task}

	# regal ignore:line-length
	assertions.assert_equal(expected, tekton.untrusted_task_refs(tasks, _empty_bundle_manifests)) with data.trusted_tasks as trusted_tasks
}

# Test untrusted_task_refs routing to rules system when trusted_task_rules data is present
test_untrusted_task_refs_routes_to_rules if {
	tasks := [trusted_bundle_task, untrusted_bundle_task]

	# Allow trusted_bundle_task pattern, deny nothing
	task_rules := {
		"allow": {"Allow trusty": {"pattern": "oci://registry.local/trusty:*"}},
		"deny": {},
	}

	# untrusted_bundle_task should be untrusted (doesn't match allow pattern)
	expected := {untrusted_bundle_task}

	# regal ignore:line-length
	assertions.assert_equal(expected, tekton.untrusted_task_refs(tasks, _empty_bundle_manifests)) with data.rule_data.trusted_task_rules as task_rules
}

test_is_trusted_task if {
	tekton.is_trusted_task(trusted_bundle_task, _empty_bundle_manifests) with data.trusted_tasks as trusted_tasks
	tekton.is_trusted_task(trusted_git_task, _empty_bundle_manifests) with data.trusted_tasks as trusted_tasks

	not tekton.is_trusted_task(untrusted_bundle_task, _empty_bundle_manifests) with data.trusted_tasks as trusted_tasks
	not tekton.is_trusted_task(untrusted_git_task, _empty_bundle_manifests) with data.trusted_tasks as trusted_tasks
	not tekton.is_trusted_task(expired_trusted_git_task, _empty_bundle_manifests) with data.trusted_tasks as trusted_tasks

	# regal ignore:line-length
	not tekton.is_trusted_task(expired_trusted_bundle_task, _empty_bundle_manifests) with data.trusted_tasks as trusted_tasks
}

# =============================================================================
# RULES SYSTEM TESTS (trusted_task_rules)
# Tests for pattern-based allow/deny rules.
# =============================================================================

test_is_trusted_task_with_rules if {
	# Test with trusted_task_rules using allow/deny patterns
	trusted_task_rules := {
		"allow": {
			"Allow konflux tasks": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			},
			"Allow registry.local tasks": {
				"pattern": "oci://registry.local/*",
			},
			"Allow specific version range of a task": {
				"pattern": "oci://quay.io/konflux-ci/another-catalog/allow-task-constrained",
				"versions": [">1.2.3", "<2"],
			},
		},
		"deny": {
			"Deny old buildah": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
			},
			"Constrain version of task": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/deny-task-constrained",
				"versions": ["<=1", ">1.2.3"],
			},
		},
	}

	# Task that matches allow rule should be trusted
	allowed_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-something:0.4@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-something"},
		{"name": "kind", "value": "task"},
	]}}}
	allowed_task_manifests := _mock_bundle_manifests(
		"quay.io/konflux-ci/tekton-catalog/task-something:0.4@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700",
		"0.4",
	)

	# regal ignore:line-length
	tekton.is_trusted_task(allowed_task, allowed_task_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules

	# Task that matches deny rule should not be trusted (deny takes precedence)
	denied_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-buildah"},
		{"name": "kind", "value": "task"},
	]}}}
	denied_task_manifests := _mock_bundle_manifests(
		"quay.io/konflux-ci/tekton-catalog/task-buildah:0.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700",
		"0.3",
	)

	# regal ignore:line-length
	not tekton.is_trusted_task(denied_task, denied_task_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules

	# Task that matches allow pattern (registry.local) should be trusted
	# Note: The key format is oci://registry.local/trusty:1.0 (with tag), so pattern oci://registry.local/* matches
	registry_local_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]}}}
	registry_local_manifests := _mock_bundle_manifests("registry.local/trusty:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.0")

	# regal ignore:line-length
	tekton.is_trusted_task(registry_local_task, registry_local_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules

	# Task that doesn't match any allow rule should not be trusted
	# Note: This task uses a different path (untrusted) that doesn't match the pattern
	not_allowed_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "other-registry.io/untrusted:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "untrusted"},
		{"name": "kind", "value": "task"},
	]}}}
	not_allowed_manifests := _mock_bundle_manifests("other-registry.io/untrusted:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.0")

	# regal ignore:line-length
	not tekton.is_trusted_task(not_allowed_task, not_allowed_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules

	# Tasks satisfying at least one deny rule version constraints should be denied
	deny_constrained_task_denied_version := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/deny-task-constrained:1.5@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "constrained"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	deny_constrained_denied_manifests := _mock_bundle_manifests("quay.io/konflux-ci/tekton-catalog/deny-task-constrained:1.5@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.5")

	# regal ignore:line-length
	not tekton.is_trusted_task(deny_constrained_task_denied_version, deny_constrained_denied_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules

	# Task not satisfying any deny rule version constraints should not be denied
	deny_constrained_task_valid_version := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/deny-task-constrained:1.2.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "constrained"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	deny_constrained_valid_manifests := _mock_bundle_manifests("quay.io/konflux-ci/tekton-catalog/deny-task-constrained:1.2.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.2.3")
	tekton.is_trusted_task(deny_constrained_task_valid_version, deny_constrained_valid_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules # regal ignore:line-length

	# Tasks satisfying all the allow-rule version constraints should be allowed
	allow_constrained_task_valid_version := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/another-catalog/allow-task-constrained:1.5@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "constrained"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	allow_constrained_valid_manifests := _mock_bundle_manifests("quay.io/konflux-ci/another-catalog/allow-task-constrained:1.5@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.5")
	tekton.is_trusted_task(allow_constrained_task_valid_version, allow_constrained_valid_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules # regal ignore:line-length

	# Tasks *NOT* satisfying all the allow-rule version constraints should be denied
	allow_constrained_task_denied_version := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/another-catalog/allow-task-constrained:1.2.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "constrained"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	allow_constrained_denied_manifests := _mock_bundle_manifests("quay.io/konflux-ci/another-catalog/allow-task-constrained:1.2.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.2.3")
	not tekton.is_trusted_task(allow_constrained_task_denied_version, allow_constrained_denied_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules # regal ignore:line-length

	# Task with mismatching versions between ref and manifest annotations.
	# Only the manifest annotation is taken into consideration
	allow_constrained_task_denied_version_mismatching_1 := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/another-catalog/allow-task-constrained:1.5@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "constrained"},
		{"name": "kind", "value": "task"},
	]}}}

	# Manifest has 1.2.3 even though ref has 1.5 - manifest version is used
	# regal ignore:line-length
	mismatch_manifests_1 := _mock_bundle_manifests("quay.io/konflux-ci/another-catalog/allow-task-constrained:1.5@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.2.3")
	not tekton.is_trusted_task(allow_constrained_task_denied_version_mismatching_1, mismatch_manifests_1) with data.rule_data.trusted_task_rules as trusted_task_rules # regal ignore:line-length

	# Task with mismatching versions between ref and manifest annotations.
	# Only the manifest annotation is taken into consideration
	allow_constrained_task_denied_version_mismatching_2 := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/another-catalog/allow-task-constrained:1.2.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "constrained"},
		{"name": "kind", "value": "task"},
	]}}}

	# Manifest has 1.5 even though ref has 1.2.3 - manifest version is used
	# regal ignore:line-length
	mismatch_manifests_2 := _mock_bundle_manifests("quay.io/konflux-ci/another-catalog/allow-task-constrained:1.2.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "1.5")
	tekton.is_trusted_task(allow_constrained_task_denied_version_mismatching_2, mismatch_manifests_2) with data.rule_data.trusted_task_rules as trusted_task_rules # regal ignore:line-length

	# Digest-only bundle reference (no tag). The key becomes "oci://repo" without tag or digest.
	# Pattern must match the repo without tag/digest components.
	digest_only_rules := {
		"allow": {
			"Allow digest-only from registry.local": {
				"pattern": "oci://registry.local/*",
			},
		},
		"deny": {
			"Deny crook digest-only": {
				"pattern": "oci://registry.local/crook",
			},
		},
	}

	# Digest-only task: key is "oci://registry.local/trusty" (no tag)
	digest_only_allowed := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/trusty@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]}}}
	tekton.is_trusted_task(digest_only_allowed, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as digest_only_rules

	# Digest-only task matching deny: key is "oci://registry.local/crook" (no tag)
	digest_only_denied := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/crook@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "crook"},
		{"name": "kind", "value": "task"},
	]}}}
	not tekton.is_trusted_task(digest_only_denied, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as digest_only_rules
}

test_trusted_task_records if {
	task_ref_expected_matches := {
		"oci://registry.local/trusty:1.0": 3,
		"oci://registry.local/trusty": 3,
		"git+git.local/repo.git//tasks/honest-abe.yaml": 2,
		"git+git.local/repo.git//tasks/untrusted.yaml": 0,
		"oci://reg": 0,
	}

	every ref, expected in task_ref_expected_matches {
		records := tekton.trusted_task_records(ref) with data.trusted_tasks as trusted_tasks
		assertions.assert_equal(expected, count(records))
	}
}

test_unexpired_records if {
	expected_refs_by_index := {
		0: "sha256:1a7e5700000000000000000000000000000000000000000000000000001a7e57",
		1: "sha256:d19e5710000000000000000000000000000000000000000000000000d19e5710",
		2: "sha256:d19e5720000000000000000000000000000000000000000000000000d19e5720",
		3: "sha256:01de5700000000000000000000000000000000000000000000000000001de570",
	}

	# regal ignore:line-length
	sorted_tasks := tekton.trusted_task_records("oci://registry.local/trusty:1.0") with data.trusted_tasks as unsorted_trusted_task
	every index, ref in expected_refs_by_index {
		assertions.assert_equal(ref, sorted_tasks[index].ref)
	}
}

test_rule_data_merging if {
	assertions.assert_equal(tekton._trusted_tasks_data.foo, "baz") with data.trusted_tasks as {"foo": "baz"}

	assertions.assert_equal(tekton._trusted_tasks_data.foo, "bar") with data.trusted_tasks as {"foo": "baz"}
		with data.rule_data.trusted_tasks as {"foo": "bar"}
}

test_data_trusted_task_rules_extraction if {
	# Test extraction from data.trusted_task_rules (covers lines 144-156)
	# Test when data.trusted_task_rules is provided with allow rules
	data_rules_allow := {"allow": {
		"Allow from data": {
			"pattern": "oci://registry.local/*",
		},
	}}

	# Task matching allow from data.trusted_task_rules should be trusted
	allowed_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]}}}
	tekton.is_trusted_task(allowed_task, _empty_bundle_manifests) with data.trusted_task_rules as data_rules_allow
		with data.rule_data.trusted_task_rules as null

	# Test when data.trusted_task_rules is provided with deny rules
	data_rules_deny := {"deny": {
		"Deny from data": {
			"pattern": "oci://registry.local/crook/*",
		},
	}}

	# Task matching deny from data.trusted_task_rules should not be trusted
	denied_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/crook:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "crook"},
		{"name": "kind", "value": "task"},
	]}}}
	not tekton.is_trusted_task(denied_task, _empty_bundle_manifests) with data.trusted_task_rules as data_rules_deny
		with data.rule_data.trusted_task_rules as null

	# Test when data.trusted_task_rules is not provided (covers default cases 145, 152)
	# Should fall back to empty arrays, so task won't be trusted via rules
	not tekton.is_trusted_task(allowed_task, _empty_bundle_manifests) with data.trusted_task_rules as null
		with data.rule_data.trusted_task_rules as null

}

test_rule_data_trusted_task_rules_extraction if {
	# Test extraction from lib_rule_data("trusted_task_rules") (covers lines 158-172)
	# Test when lib_rule_data returns an object
	rule_data_rules := {
		"allow": {
			"Allow from rule_data": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			},
		},
		"deny": {
			"Deny from rule_data": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
			},
		},
	}

	# Task matching allow from rule_data should be trusted
	allowed_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-something:0.4@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-something"},
		{"name": "kind", "value": "task"},
	]}}}
	tekton.is_trusted_task(allowed_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as rule_data_rules

	# Task matching deny from rule_data should not be trusted
	denied_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-buildah"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	not tekton.is_trusted_task(denied_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as rule_data_rules

	# Test when lib_rule_data returns [] (not an object) - covers default cases
	# When rule_data returns [], it's not an object, so defaults are used
	not tekton.is_trusted_task(allowed_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as []
}

test_data_errors if {
	tasks := {
		"not-an-array": 1,
		"empty-array": [],
		"missing-required-properties": [{}],
		"additional-properties": [{
			"effective_on": "2024-01-01T00:00:00Z",
			"expires_on": "2024-02-01T00:00:00Z",
			"ref": "abc",
			"spam": "maps",
		}],
		"bad-dates": [
			{"ref": "bad-effective-on", "effective_on": "not-a-date"},
			{"ref": "bad-effective-on", "effective_on": "2024-01-01T00:00:00Z", "expires_on": "not-a-date"},
		],
		# this is allowed
		"duplicated-entries": [
			# regal ignore:line-length
			{"ref": "sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "expires_on": "2099-01-01T00:00:00Z"},
			# regal ignore:line-length
			{"ref": "sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700", "expires_on": "2099-01-01T00:00:00Z"},
		],
	}

	expected := {
		{
			"message": "trusted_tasks data has unexpected format: not-an-array: Invalid type. Expected: array, given: integer",
			"severity": "failure",
		},
		{
			"message": "trusted_tasks data has unexpected format: empty-array: Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"message": "trusted_tasks data has unexpected format: missing-required-properties.0: ref is required",
			"severity": "failure",
		},
		{
			# regal ignore:line-length
			"message": "trusted_tasks data has unexpected format: additional-properties.0: Additional property spam is not allowed",
			"severity": "warning",
		},
		{
			"message": `trusted_tasks.bad-dates[0].effective_on is not valid RFC3339 format: "not-a-date"`,
			"severity": "failure",
		},
		{
			"message": `trusted_tasks.bad-dates[1].expires_on is not valid RFC3339 format: "not-a-date"`,
			"severity": "failure",
		},
	}

	assertions.assert_equal(tekton.data_errors, expected) with data.trusted_tasks as tasks
}

test_task_expiry_warning_days_data if {
	assertions.assert_equal(tekton.data_errors, {{
		"message": "task_expiry_warning_days: Invalid type. Expected: integer, given: string",
		"severity": "failure",
	}}) with data.rule_data.task_expiry_warning_days as "14"

	assertions.assert_equal(tekton.data_errors, {{
		"message": `task_expiry_warning_days: Invalid type. Expected: integer, given: number`,
		"severity": "failure",
	}}) with data.rule_data.task_expiry_warning_days as 5.5

	assertions.assert_empty(tekton.data_errors) with data.rule_data.task_expiry_warning_days as 14
}

test_denying_pattern if {
	# Test that denying_pattern returns the pattern that denied a task
	trusted_task_rules := {
		"allow": {},
		"deny": {
			"Deny old buildah": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
			},
		},
	}

	# Create a task that matches the deny rule
	denied_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-buildah"},
		{"name": "kind", "value": "task"},
	]}}}

	# Should return a list with the pattern that denied it
	# regal ignore:line-length
	patterns := tekton.denying_pattern(denied_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules
	assertions.assert_equal(["oci://quay.io/konflux-ci/tekton-catalog/task-buildah*"], patterns)

	# Task that doesn't match any deny rule should return empty list
	non_matching_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "trusty"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	patterns_empty := tekton.denying_pattern(non_matching_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules
	assertions.assert_equal([], patterns_empty)
}

test_denying_pattern_multiple_rules if {
	# Test with multiple deny rules - should return one of the matching patterns
	multiple_deny_rules := {
		"allow": {},
		"deny": {
			"Deny all konflux": {
				"pattern": "oci://quay.io/konflux-ci/*",
			},
			"Deny buildah specifically": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
			},
		},
	}

	# Should match both patterns (both rules match this task)
	buildah_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-buildah"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	patterns_multi := tekton.denying_pattern(buildah_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as multiple_deny_rules

	# Should contain both patterns (order may vary)
	assertions.assert_equal(2, count(patterns_multi))
	every pattern in patterns_multi {
		pattern in {
			"oci://quay.io/konflux-ci/*",
			"oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
		}
	}
}

test_denial_reason if {
	# Test denial_reason returns the correct reason for denied tasks
	trusted_task_rules := {
		"allow": {
			"Allow konflux tasks": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			},
		},
		"deny": {
			"Deny old buildah": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
				"message": "This version is deprecated",
			},
		},
	}

	# Case 1: Matches a deny rule (even though it also matches allow)
	denied_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.3@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-buildah"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	reason_deny := tekton.denial_reason(denied_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules
	assertions.assert_equal("deny_rule", reason_deny.type)
	assertions.assert_equal(["oci://quay.io/konflux-ci/tekton-catalog/task-buildah*"], reason_deny.pattern)
	assertions.assert_equal(["This version is deprecated"], reason_deny.messages)

	# Case 2: Doesn't match any allow rule and isn't in legacy
	not_allowed_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/untrusted:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "untrusted"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	reason_not_allowed := tekton.denial_reason(not_allowed_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules
	assertions.assert_equal("not_allowed", reason_not_allowed.type)
	assertions.assert_equal([], reason_not_allowed.pattern)
	assertions.assert_equal([], reason_not_allowed.messages)

	# Task that matches allow rule should return nothing (it's trusted)
	allowed_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-something:0.4@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-something"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	not tekton.denial_reason(allowed_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules

	# Task in legacy trusted_tasks but doesn't match allow rules should return "not_allowed"
	# (denial_reason only works with trusted_task_rules, not legacy)
	# regal ignore:line-length
	reason_legacy := tekton.denial_reason(trusted_bundle_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as trusted_task_rules
		with data.trusted_tasks as trusted_tasks
	assertions.assert_equal("not_allowed", reason_legacy.type)
	assertions.assert_equal([], reason_legacy.pattern)
	assertions.assert_equal([], reason_legacy.messages)
}

test_denial_reason_no_allow_rules if {
	# If there are no allow rules, we fall back to legacy, so "not_allowed" shouldn't apply
	rules_no_allow := {
		"allow": {},
		"deny": {},
	}

	# Task not in legacy should return nothing (we fall back to legacy, which is empty, but denial_reason
	# only applies when allow rules exist)
	untrusted_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "registry.local/untrusted:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "untrusted"},
		{"name": "kind", "value": "task"},
	]}}}

	# regal ignore:line-length
	not tekton.denial_reason(untrusted_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as rules_no_allow
}

test_trusted_task_rules_data_errors if {
	# When trusted_task_rules is not provided (defaults to []), validation should be skipped
	assertions.assert_empty(tekton.data_errors)

	# Valid empty object should pass
	assertions.assert_empty(tekton.data_errors) with data.rule_data.trusted_task_rules as {}

	# Valid trusted_task_rules should pass
	valid_rules := {
		"allow": {
			"Allow all konflux tasks": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			},
		},
		"deny": {
			"Deny old buildah": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/task-buildah*",
				"effective_on": "2025-11-15",
				"message": "Deprecated",
			},
		},
	}
	assertions.assert_empty(tekton.data_errors) with data.rule_data.trusted_task_rules as valid_rules

	# Missing required fields - object entry without pattern
	invalid_rules := {"allow": {"Bad entry": {}}}
	expected := {{
		# regal ignore:line-length
		"message": "trusted_task_rules data has unexpected format: allow.Bad entry: pattern is required",
		"severity": "failure",
	}}
	assertions.assert_equal(tekton.data_errors, expected) with data.rule_data.trusted_task_rules as invalid_rules

	# Invalid effective_on date format
	invalid_date_rules := {"allow": {
		"Invalid date": {
			"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			"effective_on": "not-a-date",
		},
	}}
	expected_date := {{
		# regal ignore:line-length
		"message": "trusted_task_rules data has unexpected format: allow.Invalid date.effective_on: Does not match format 'date'",
		"severity": "failure",
	}}
	assertions.assert_equal(tekton.data_errors, expected_date) with data.rule_data.trusted_task_rules as invalid_date_rules

	# Invalid structure - not an object
	assertions.assert_empty(tekton.data_errors) with data.rule_data.trusted_task_rules as [] # Empty list is skipped

	# Invalid allow/deny - not objects
	invalid_structure := {
		"allow": "not-an-object",
		"deny": {
			"Valid deny": {
				"pattern": "oci://quay.io/konflux-ci/tekton-catalog/*",
			},
		},
	}
	expected_structure := {{
		# regal ignore:line-length
		"message": "trusted_task_rules data has unexpected format: allow: Invalid type. Expected: object, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal(tekton.data_errors, expected_structure) with data.rule_data.trusted_task_rules as invalid_structure
}

# Test denying_pattern with invalid task (covers else branch at line 337)
test_denying_pattern_invalid_task if {
	# Task with no valid ref - should return empty list
	invalid_task := {"spec": {}}

	# Any rules - doesn't matter since task has no valid ref
	rules := {
		"allow": {},
		"deny": {
			"Deny something": {
				"pattern": "oci://quay.io/*",
			},
		},
	}

	# Should return empty list (else branch) since task_ref fails
	# regal ignore:line-length
	patterns := tekton.denying_pattern(invalid_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as rules
	assertions.assert_equal([], patterns)
}

# Test that _denying_rules_info returns empty when no deny rules match
# This covers the else branch at line 384
test_denying_rules_info_empty if {
	# Rules with no deny rules
	rules_no_deny := {
		"allow": {
			"Allow all": {
				"pattern": "oci://quay.io/*",
			},
		},
		"deny": {},
	}

	# Task that matches allow rule - denial_reason should be empty
	allowed_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
		# regal ignore:line-length
		{"name": "bundle", "value": "quay.io/konflux-ci/tekton-catalog/task-buildah:0.4@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{"name": "name", "value": "task-buildah"},
		{"name": "kind", "value": "task"},
	]}}}

	# denial_reason returns nothing for allowed tasks (internally calls _denying_rules_info which returns empty)
	not tekton.denial_reason(allowed_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as rules_no_deny

	# denying_pattern should also return empty list (covers line 337)
	# regal ignore:line-length
	patterns := tekton.denying_pattern(allowed_task, _empty_bundle_manifests) with data.rule_data.trusted_task_rules as rules_no_deny
	assertions.assert_equal([], patterns)
}

trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	# regal ignore:line-length
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

newest_trusted_bundle_task := trusted_bundle_task

same_date_trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	# regal ignore:line-length
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:5a4eda7e00000000000000000000000000000000000000000000000005a4eda7e"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

outdated_trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	# regal ignore:line-length
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:007da7edd19e5700000000000000000000000000000000007da7edd19e57"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

expired_trusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	# regal ignore:line-length
	{"name": "bundle", "value": "registry.local/trusty:1.0@sha256:e001edd19e5700000000000000000000000000000000000000e001edd19e57"},
	{"name": "name", "value": "trusty"},
	{"name": "kind", "value": "task"},
]}}}

unpinned_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	{"name": "bundle", "value": "registry.local/trusty:1.0"},
	{"name": "name", "value": "crook"},
	{"name": "kind", "value": "task"},
]}}}

untrusted_bundle_task := {"spec": {"taskRef": {"resolver": "bundles", "params": [
	# regal ignore:line-length
	{"name": "bundle", "value": "registry.local/crook:1.0@sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
	{"name": "name", "value": "crook"},
	{"name": "kind", "value": "task"},
]}}}

trusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "48df630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

newest_trusted_git_task := trusted_git_task

outdated_trusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

expired_trusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "26ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

unpinned_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "honest-abe"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "main"},
		{"name": "pathInRepo", "value": "tasks/honest-abe.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

untrusted_git_task := {
	"metadata": {"labels": {"tekton.dev/task": "lawless"}},
	"spec": {"taskRef": {"resolver": "git", "params": [
		{"name": "revision", "value": "37ef630394794f28142224295851a45eea5c63ae"},
		{"name": "pathInRepo", "value": "tasks/lawless.yaml"},
		{"name": "url", "value": "git.local/repo.git"},
	]}},
}

# =============================================================================
# BEGIN LEGACY TEST DATA (trusted_tasks)
# DELETE THIS SECTION when removing legacy support.
# =============================================================================

trusted_tasks := {
	"oci://registry.local/trusty:1.0": [
		{"ref": "sha256:d19e5700000000000000000000000000000000000000000000000000d19e5700"},
		{
			"ref": "sha256:5a4eda7e00000000000000000000000000000000000000000000000005a4eda7e",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:007da7edd19e5700000000000000000000000000000000007da7edd19e57",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "sha256:e001edd19e5700000000000000000000000000000000000000e001edd19e57",
			"expires_on": "2024-01-01T00:00:00Z",
		},
	],
	"git+git.local/repo.git//tasks/honest-abe.yaml": [
		{"ref": "48df630394794f28142224295851a45eea5c63ae"},
		{
			"ref": "37ef630394794f28142224295851a45eea5c63ae",
			"expires_on": "2099-01-01T00:00:00Z",
		},
		{
			"ref": "26ef630394794f28142224295851a45eea5c63ae",
			"expires_on": "2024-01-01T00:00:00Z",
		},
	],
}

unsorted_trusted_task := {"oci://registry.local/trusty:1.0": [
	{
		"ref": "sha256:d19e5710000000000000000000000000000000000000000000000000d19e5710",
		"expires_on": "2100-01-01T00:00:00Z",
	},
	{
		"ref": "sha256:d19e5720000000000000000000000000000000000000000000000000d19e5720",
		"expires_on": "2075-01-01T00:00:00Z",
	},
	{"ref": "sha256:1a7e5700000000000000000000000000000000000000000000000000001a7e57"},
	{
		"ref": "sha256:01de5700000000000000000000000000000000000000000000000000001de570",
		"expires_on": "2050-01-01T00:00:00Z",
	},
	{
		"ref": "sha256:e001ed00000000000000000000000000000000000000000000000000e001ed00",
		"expires_on": "2000-01-01T00:00:00Z",
	},
	{
		"ref": "sha256:bad0da7e0000000000000000000000000000000000000000000000bad0da7e",
		"expires_on": "bad-data",
	},
]}

test_version_satisfies_all_rule_constraints if {
	# No version constraints in rule - should always pass
	tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.2.3"}, {}, _empty_bundle_manifests)

	# Has version constraints and valid semver
	manifests_1_2_3 := _mock_bundle_manifests("example.com/task:1.0", "1.2.3")

	# regal ignore:line-length
	tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=1.1", "<3"]}, manifests_1_2_3)
	manifests_1_1_0 := _mock_bundle_manifests("example.com/task:1.0", "1.1.0")

	# regal ignore:line-length
	tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=1.1", "<3"]}, manifests_1_1_0)
	manifests_1_1_1 := _mock_bundle_manifests("example.com/task:1.0", "v1.1.1")

	# regal ignore:line-length
	tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<3"]}, manifests_1_1_1)
	manifests_3_0_0 := _mock_bundle_manifests("example.com/task:1.0", "v3.0.0")

	# regal ignore:line-length
	tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<=3"]}, manifests_3_0_0)

	# Version doesn't match all the constraints
	manifests_1_5_0 := _mock_bundle_manifests("example.com/task:1.0", "v1.5.0")

	# regal ignore:line-length
	not tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=2"]}, manifests_1_5_0)
	manifests_v1_1_0 := _mock_bundle_manifests("example.com/task:1.0", "v1.1.0")

	# regal ignore:line-length
	not tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<3"]}, manifests_v1_1_0)
	manifests_v3_0_0 := _mock_bundle_manifests("example.com/task:1.0", "v3.0.0")

	# regal ignore:line-length
	not tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<3"]}, manifests_v3_0_0)

	# regal ignore:line-length
	not tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": ["<2", ">=1.5.1"]}, manifests_1_5_0)

	# Invalid inputs - should fail
	manifests_empty := {"example.com/task:1.0": {"annotations": {}}}

	# regal ignore:line-length
	not tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=2"]}, manifests_empty)
	manifests_invalid := _mock_bundle_manifests("example.com/task:1.0", "invalid")

	# regal ignore:line-length
	not tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=2"]}, manifests_invalid)
}

test_version_satisfies_any_rule_constraints if {
	# No version constraints in rule - should always pass
	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.2.3"}, {}, _empty_bundle_manifests)

	# Has version constraints and valid semver
	manifests_v1_2_3 := _mock_bundle_manifests("example.com/task:1.0", "v1.2.3")

	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=1.1", "<3"]}, manifests_v1_2_3)
	manifests_v1_1_0 := _mock_bundle_manifests("example.com/task:1.0", "v1.1.0")

	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=1.1", "<3"]}, manifests_v1_1_0)
	manifests_v1_1_1 := _mock_bundle_manifests("example.com/task:1.0", "v1.1.1")

	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<3"]}, manifests_v1_1_1)
	manifests_v3_0_0 := _mock_bundle_manifests("example.com/task:1.0", "v3.0.0")

	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<=3"]}, manifests_v3_0_0)

	# Version doesn't match all the constraints, but still passes
	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<3"]}, manifests_v1_1_0)

	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">1.1", "<3"]}, manifests_v3_0_0)

	# Version doesn't match any constraint
	manifests_v1_5_0 := _mock_bundle_manifests("example.com/task:1.0", "v1.5.0")

	# regal ignore:line-length
	not tekton._version_satisfies_all_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=2"]}, manifests_v1_5_0)

	# regal ignore:line-length
	not tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": ["<1", ">=1.5.1"]}, manifests_v1_5_0)

	# Missing or invalid version annotation - should return true (deny by default for security)
	manifests_empty := {"example.com/task:1.0": {"annotations": {}}}

	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=2"]}, manifests_empty)
	manifests_invalid := _mock_bundle_manifests("example.com/task:1.0", "invalid")

	# regal ignore:line-length
	tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": [">=2"]}, manifests_invalid)

	# regal ignore:line-length
	not tekton._version_satisfies_any_rule_constraints({"bundle": "example.com/task:1.0"}, {"versions": ["<1", ">=1.5.1"]}, manifests_v1_5_0)
}

test_normalize_version if {
	# Trim operators
	assertions.assert_equal("1.2.3", tekton._normalize_version(">=1.2.3"))
	assertions.assert_equal("1.2.3", tekton._normalize_version("<=1.2.3"))
	assertions.assert_equal("1.2.3", tekton._normalize_version(">1.2.3"))
	assertions.assert_equal("1.2.3", tekton._normalize_version("<1.2.3"))

	# Trim operators and 'v' prefix
	assertions.assert_equal("1.2.3", tekton._normalize_version(">=v1.2.3"))
	assertions.assert_equal("1.2.3", tekton._normalize_version("<=v1.2.3"))
	assertions.assert_equal("1.2.3", tekton._normalize_version(">v1.2.3"))
	assertions.assert_equal("1.2.3", tekton._normalize_version("<v1.2.3"))

	# Normalize version ranges
	assertions.assert_equal("1.2.0", tekton._normalize_version(">=v1.2"))
	assertions.assert_equal("1.0.0", tekton._normalize_version(">=v1"))
}

test_result_satisfies_operator if {
	# >= operator
	tekton._result_satisfies_operator(1, ">=2")
	tekton._result_satisfies_operator(0, ">=2")
	not tekton._result_satisfies_operator(-1, ">=2")

	# > operator
	tekton._result_satisfies_operator(1, ">2")
	not tekton._result_satisfies_operator(0, ">2")
	not tekton._result_satisfies_operator(-1, ">2")

	# <= operator
	not tekton._result_satisfies_operator(1, "<=2")
	tekton._result_satisfies_operator(0, "<=2")
	tekton._result_satisfies_operator(-1, "<=2")

	# < operator
	not tekton._result_satisfies_operator(1, "<2")
	not tekton._result_satisfies_operator(0, "<2")
	tekton._result_satisfies_operator(-1, "<2")
}

# Mock function for ec.oci.image_manifests
_mock_image_manifests(refs) := {ref: {} | some ref in refs}

# Mock function for ec.oci.image_manifest (singular)
_mock_image_manifest(_) := {}

test_mock_image_manifests if {
	result := _mock_image_manifests({"ref1", "ref2"})
	expected := {"ref1": {}, "ref2": {}}
	assertions.assert_equal(expected, result)
}

test_mock_image_manifest if {
	result := _mock_image_manifest("any-ref")
	assertions.assert_equal({}, result)
}
