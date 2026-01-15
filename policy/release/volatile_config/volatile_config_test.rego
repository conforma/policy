# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

package volatile_config_test

import rego.v1

import data.lib
import data.lib.time as time_lib
import data.volatile_config

# Use a fixed "now" time for deterministic tests: 2024-06-15T12:00:00Z
_now_ns := 1718452800000000000

_image_ref := "quay.io/repo/image:v1@sha256:abc123def456"

_image_digest := "sha256:abc123def456"

_component_name := "my-component"

# =============================================================================
# Test: pending_rule warning
# =============================================================================

test_warn_pending_rule if {
	policy_spec := _policy_spec_with_include({
		"value": "cve.cve_blockers",
		"effectiveOn": "2024-07-15T12:00:00Z",
	})

	expected := {{
		"code": "volatile_config.pending_rule",
		"msg": "Volatile include rule 'cve.cve_blockers' is pending activation (effective on: 2024-07-15T12:00:00Z)",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_pending_rule_exclude if {
	policy_spec := _policy_spec_with_exclude({
		"value": "test.some_test",
		"effectiveOn": "2024-07-15T12:00:00Z",
	})

	expected := {{
		"code": "volatile_config.pending_rule",
		"msg": "Volatile exclude rule 'test.some_test' is pending activation (effective on: 2024-07-15T12:00:00Z)",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Test: expiring_rule warning
# =============================================================================

test_warn_expiring_rule if {
	# 15 days until expiration
	policy_spec := _policy_spec_with_include({
		"value": "sbom.disallowed_packages",
		"effectiveUntil": "2024-06-30T12:00:00Z",
	})

	expected := {{
		"code": "volatile_config.expiring_rule",
		"msg": "Volatile include rule 'sbom.disallowed_packages' expires in 15 days (effective until: 2024-06-30T12:00:00Z)",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_no_warn_expiring_beyond_threshold if {
	# 60 days until expiration (beyond 30-day threshold)
	policy_spec := _policy_spec_with_include({
		"value": "sbom.disallowed_packages",
		"effectiveUntil": "2024-08-14T12:00:00Z",
	})

	lib.assert_empty(volatile_config.warn) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_expiring_custom_threshold if {
	# 10 days until expiration, threshold set to 14
	policy_spec := _policy_spec_with_include({
		"value": "test.rule",
		"effectiveUntil": "2024-06-25T12:00:00Z",
	})

	expected := {{
		"code": "volatile_config.expiring_rule",
		"msg": "Volatile include rule 'test.rule' expires in 10 days (effective until: 2024-06-25T12:00:00Z)",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
		with data.rule_data__configuration__.volatile_config_warning_threshold_days as 14
}

# =============================================================================
# Test: no_expiration warning
# =============================================================================

test_warn_no_expiration if {
	policy_spec := _policy_spec_with_include({"value": "permanent.exception"})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'permanent.exception' has no expiration date set",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_no_expiration_with_past_effective_on if {
	policy_spec := _policy_spec_with_include({
		"value": "active.rule",
		"effectiveOn": "2024-06-01T12:00:00Z",
	})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'active.rule' has no expiration date set",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Test: expired_rule warning
# =============================================================================

test_warn_expired_rule if {
	policy_spec := _policy_spec_with_include({
		"value": "old.exception",
		"effectiveUntil": "2024-06-05T12:00:00Z",
	})

	expected := {{
		"code": "volatile_config.expired_rule",
		"msg": "Volatile include rule 'old.exception' has expired (effective until: 2024-06-05T12:00:00Z)",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Test: invalid_config warning
# =============================================================================

test_warn_invalid_config_effective_on if {
	policy_spec := _policy_spec_with_include({
		"value": "broken.rule",
		"effectiveOn": "not-a-date",
	})

	expected := {{
		"code": "volatile_config.invalid_config",
		# regal ignore:line-length
		"msg": "Volatile include rule 'broken.rule' has invalid date configuration (effectiveOn: not-a-date, effectiveUntil: )",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_invalid_config_effective_until if {
	policy_spec := _policy_spec_with_include({
		"value": "broken.rule",
		"effectiveUntil": "invalid",
	})

	expected := {{
		"code": "volatile_config.invalid_config",
		"msg": "Volatile include rule 'broken.rule' has invalid date configuration (effectiveOn: , effectiveUntil: invalid)",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Test: image scoping
# =============================================================================

test_warn_scoped_by_image_digest_match if {
	policy_spec := _policy_spec_with_include({
		"value": "scoped.rule",
		"imageDigest": _image_digest,
	})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'scoped.rule' has no expiration date set",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_no_warn_scoped_by_image_digest_no_match if {
	policy_spec := _policy_spec_with_include({
		"value": "scoped.rule",
		"imageDigest": "sha256:different",
	})

	lib.assert_empty(volatile_config.warn) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_scoped_by_component_name_match if {
	policy_spec := _policy_spec_with_include({
		"value": "component.rule",
		"componentNames": [_component_name],
	})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'component.rule' has no expiration date set",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_no_warn_scoped_by_component_name_no_match if {
	policy_spec := _policy_spec_with_include({
		"value": "component.rule",
		"componentNames": ["other-component"],
	})

	lib.assert_empty(volatile_config.warn) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_scoped_by_image_url_match if {
	policy_spec := _policy_spec_with_include({
		"value": "url.rule",
		"imageUrl": "quay.io/repo/image",
	})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'url.rule' has no expiration date set",
	}}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Test: multiple rules and sources
# =============================================================================

test_warn_multiple_rules if {
	policy_spec := {"sources": [{
		"name": "test-source",
		"volatileConfig": {
			"include": [
				{"value": "include.rule"},
				{"value": "pending.rule", "effectiveOn": "2024-07-15T12:00:00Z"},
			],
			"exclude": [{"value": "exclude.rule"}],
		},
	}]}

	expected := {
		{
			"code": "volatile_config.no_expiration",
			"msg": "Volatile include rule 'include.rule' has no expiration date set",
		},
		{
			"code": "volatile_config.pending_rule",
			"msg": "Volatile include rule 'pending.rule' is pending activation (effective on: 2024-07-15T12:00:00Z)",
		},
		{
			"code": "volatile_config.no_expiration",
			"msg": "Volatile exclude rule 'exclude.rule' has no expiration date set",
		},
	}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_multiple_sources if {
	policy_spec := {"sources": [
		{
			"name": "source-1",
			"volatileConfig": {"include": [{"value": "source1.rule"}]},
		},
		{
			"name": "source-2",
			"volatileConfig": {"include": [{"value": "source2.rule"}]},
		},
	]}

	expected := {
		{
			"code": "volatile_config.no_expiration",
			"msg": "Volatile include rule 'source1.rule' has no expiration date set",
		},
		{
			"code": "volatile_config.no_expiration",
			"msg": "Volatile include rule 'source2.rule' has no expiration date set",
		},
	}

	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Test: no warnings when policy_spec is empty/missing
# =============================================================================

test_no_warn_no_policy_spec if {
	lib.assert_empty(volatile_config.warn) with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_no_warn_no_volatile_config if {
	policy_spec := {"sources": [{"name": "test-source"}]}

	lib.assert_empty(volatile_config.warn) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_no_warn_empty_volatile_config if {
	policy_spec := {"sources": [{
		"name": "test-source",
		"volatileConfig": {},
	}]}

	lib.assert_empty(volatile_config.warn) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Test: image ref edge cases
# =============================================================================

test_warn_with_no_image_ref if {
	policy_spec := _policy_spec_with_include({"value": "global.rule"})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'global.rule' has no expiration date set",
	}}

	# Global rules apply even without image ref
	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_with_image_ref_no_digest if {
	policy_spec := _policy_spec_with_include({"value": "global.rule"})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'global.rule' has no expiration date set",
	}}

	# Global rules apply with image ref that has no digest
	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as "quay.io/repo/image:v1"
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_with_no_component_name if {
	policy_spec := _policy_spec_with_include({"value": "global.rule"})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'global.rule' has no expiration date set",
	}}

	# Global rules apply without component_name in input
	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as _image_ref
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_with_malformed_image_ref_multiple_at if {
	policy_spec := _policy_spec_with_include({"value": "global.rule"})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'global.rule' has no expiration date set",
	}}

	# Global rules apply with malformed image ref containing multiple @ symbols
	# This tests the case where split("@") doesn't produce exactly 2 parts
	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as "quay.io/repo/image@sha256:abc123@sha256:def456"
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

test_warn_with_malformed_image_ref_trailing_at if {
	policy_spec := _policy_spec_with_include({"value": "global.rule"})

	expected := {{
		"code": "volatile_config.no_expiration",
		"msg": "Volatile include rule 'global.rule' has no expiration date set",
	}}

	# Global rules apply with malformed image ref with trailing @ (no digest)
	# This tests the case where split("@") doesn't produce exactly 2 parts
	lib.assert_equal_results(volatile_config.warn, expected) with input.policy_spec as policy_spec
		with input.image.ref as "quay.io/repo/image@"
		with input.component_name as _component_name
		with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# Helper functions
# =============================================================================

_policy_spec_with_include(config) := {"sources": [{
	"name": "test-source",
	"volatileConfig": {"include": [config]},
}]}

_policy_spec_with_exclude(config) := {"sources": [{
	"name": "test-source",
	"volatileConfig": {"exclude": [config]},
}]}
