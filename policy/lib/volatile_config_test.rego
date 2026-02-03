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

package lib_test

import rego.v1

import data.lib
import data.lib.time as time_lib

# Use a fixed "now" time for deterministic tests: 2024-06-15T12:00:00Z
_now_ns := 1718452800000000000

# =============================================================================
# warning_threshold_days tests
# =============================================================================

test_warning_threshold_days_default if {
	lib.assert_equal(lib.warning_threshold_days, 30)
}

test_warning_threshold_days_custom if {
	# regal ignore:line-length
	lib.assert_equal(lib.warning_threshold_days, 14) with data.rule_data__configuration__.volatile_config_warning_threshold_days as 14
}

# =============================================================================
# days_until_expiration tests
# =============================================================================

test_days_until_expiration_positive if {
	# 10 days in the future
	rule := {"effectiveUntil": "2024-06-25T12:00:00Z"}
	lib.assert_equal(lib.days_until_expiration(rule), 10) with time_lib.effective_current_time_ns as _now_ns
}

test_days_until_expiration_negative if {
	# 5 days in the past
	rule := {"effectiveUntil": "2024-06-10T12:00:00Z"}
	lib.assert_equal(lib.days_until_expiration(rule), -5) with time_lib.effective_current_time_ns as _now_ns
}

test_days_until_expiration_zero if {
	# Same day (less than 24 hours)
	rule := {"effectiveUntil": "2024-06-15T23:59:59Z"}
	lib.assert_equal(lib.days_until_expiration(rule), 0) with time_lib.effective_current_time_ns as _now_ns
}

test_days_until_expiration_no_date if {
	rule := {"value": "some.rule"}
	not lib.days_until_expiration(rule)
}

test_days_until_expiration_empty_date if {
	rule := {"effectiveUntil": ""}
	not lib.days_until_expiration(rule)
}

test_days_until_expiration_invalid_date if {
	rule := {"effectiveUntil": "not-a-date"}
	not lib.days_until_expiration(rule)
}

# =============================================================================
# is_rule_applicable tests - global rules
# =============================================================================

test_is_rule_applicable_global if {
	rule := {"value": "some.rule"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_global_explicit_empty if {
	rule := {
		"value": "some.rule",
		"imageRef": "",
		"imageUrl": "",
		"imageDigest": "",
		"componentNames": [],
	}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

# =============================================================================
# is_rule_applicable tests - imageDigest matching
# =============================================================================

test_is_rule_applicable_image_digest_match if {
	rule := {"value": "some.rule", "imageDigest": "sha256:abc123def456"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123def456",
		"imageDigest": "sha256:abc123def456",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_image_digest_no_match if {
	rule := {"value": "some.rule", "imageDigest": "sha256:abc123def456"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:different",
		"imageDigest": "sha256:different",
		"componentName": "my-component",
	}
	not lib.is_rule_applicable(rule, context)
}

# =============================================================================
# is_rule_applicable tests - imageRef (DEPRECATED, same as imageDigest)
# =============================================================================

test_is_rule_applicable_image_ref_match if {
	rule := {"value": "some.rule", "imageRef": "sha256:abc123def456"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123def456",
		"imageDigest": "sha256:abc123def456",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_image_ref_no_match if {
	rule := {"value": "some.rule", "imageRef": "sha256:abc123def456"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:different",
		"imageDigest": "sha256:different",
		"componentName": "my-component",
	}
	not lib.is_rule_applicable(rule, context)
}

# =============================================================================
# is_rule_applicable tests - imageUrl matching
# =============================================================================

test_is_rule_applicable_image_url_exact_match if {
	rule := {"value": "some.rule", "imageUrl": "quay.io/repo/image"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_image_url_prefix_match if {
	rule := {"value": "some.rule", "imageUrl": "quay.io/repo"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_image_url_no_match if {
	rule := {"value": "some.rule", "imageUrl": "quay.io/other"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	not lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_image_url_with_tag_only if {
	rule := {"value": "some.rule", "imageUrl": "quay.io/repo/image"}
	context := {
		"imageRef": "quay.io/repo/image:v1",
		"imageDigest": "",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

# =============================================================================
# is_rule_applicable tests - componentNames matching
# =============================================================================

test_is_rule_applicable_component_name_match if {
	rule := {"value": "some.rule", "componentNames": ["my-component", "other-component"]}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_component_name_no_match if {
	rule := {"value": "some.rule", "componentNames": ["other-component"]}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	not lib.is_rule_applicable(rule, context)
}

test_is_rule_applicable_component_name_empty_list if {
	# Empty componentNames should NOT match (it's a global rule then, handled separately)
	rule := {"value": "some.rule", "componentNames": [], "imageUrl": "quay.io/other"}
	context := {
		"imageRef": "quay.io/repo/image:v1@sha256:abc123",
		"imageDigest": "sha256:abc123",
		"componentName": "my-component",
	}
	not lib.is_rule_applicable(rule, context)
}

# =============================================================================
# warning_category tests - invalid
# =============================================================================

test_warning_category_invalid_effective_on if {
	rule := {"value": "some.rule", "effectiveOn": "not-a-date"}
	lib.assert_equal(lib.warning_category(rule), "invalid") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_invalid_effective_until if {
	rule := {"value": "some.rule", "effectiveUntil": "also-not-a-date"}
	lib.assert_equal(lib.warning_category(rule), "invalid") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_empty_strings_not_invalid if {
	# Empty strings should not be considered invalid (they're just not set)
	rule := {"value": "some.rule", "effectiveOn": "", "effectiveUntil": ""}

	# Should not be "invalid" - empty strings are valid (not set)
	not lib.warning_category(rule) == "invalid" with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_invalid_on_valid_until if {
	# effectiveOn invalid, effectiveUntil valid - should be "invalid"
	rule := {
		"value": "some.rule",
		"effectiveOn": "not-a-date",
		"effectiveUntil": "2024-06-25T12:00:00Z",
	}
	lib.assert_equal(lib.warning_category(rule), "invalid") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_valid_on_invalid_until if {
	# effectiveOn valid, effectiveUntil invalid - should be "invalid"
	rule := {
		"value": "some.rule",
		"effectiveOn": "2024-06-01T12:00:00Z",
		"effectiveUntil": "not-a-date",
	}
	lib.assert_equal(lib.warning_category(rule), "invalid") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_both_dates_invalid if {
	# Both dates invalid - should be "invalid"
	rule := {
		"value": "some.rule",
		"effectiveOn": "not-a-date",
		"effectiveUntil": "also-not-a-date",
	}
	lib.assert_equal(lib.warning_category(rule), "invalid") with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# warning_category tests - pending
# =============================================================================

test_warning_category_pending if {
	# effectiveOn is 30 days in the future
	rule := {"value": "some.rule", "effectiveOn": "2024-07-15T12:00:00Z"}
	lib.assert_equal(lib.warning_category(rule), "pending") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_not_pending_when_active if {
	# effectiveOn is in the past
	rule := {"value": "some.rule", "effectiveOn": "2024-06-01T12:00:00Z"}

	# Should not be "pending" - it should be "no_expiration" since no effectiveUntil
	lib.assert_equal(lib.warning_category(rule), "no_expiration") with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# warning_category tests - expired
# =============================================================================

test_warning_category_expired if {
	# effectiveUntil is 10 days in the past
	rule := {"value": "some.rule", "effectiveUntil": "2024-06-05T12:00:00Z"}
	lib.assert_equal(lib.warning_category(rule), "expired") with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# warning_category tests - expiring
# =============================================================================

test_warning_category_expiring_within_threshold if {
	# effectiveUntil is 15 days in the future (within 30-day threshold)
	rule := {"value": "some.rule", "effectiveUntil": "2024-06-30T12:00:00Z"}
	lib.assert_equal(lib.warning_category(rule), "expiring") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_expiring_at_threshold if {
	# effectiveUntil is exactly 30 days in the future
	rule := {"value": "some.rule", "effectiveUntil": "2024-07-15T12:00:00Z"}
	lib.assert_equal(lib.warning_category(rule), "expiring") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_not_expiring_beyond_threshold if {
	# effectiveUntil is 60 days in the future (beyond 30-day threshold)
	rule := {"value": "some.rule", "effectiveUntil": "2024-08-14T12:00:00Z"}

	# Should not produce a category (no warning needed)
	not lib.warning_category(rule) with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_expiring_custom_threshold if {
	# effectiveUntil is 10 days in the future, threshold is 7 days
	rule := {"value": "some.rule", "effectiveUntil": "2024-06-25T12:00:00Z"}

	# 10 days > 7 day threshold, so no warning
	not lib.warning_category(rule) with time_lib.effective_current_time_ns as _now_ns
		with data.rule_data__configuration__.volatile_config_warning_threshold_days as 7
}

# =============================================================================
# warning_category tests - no_expiration
# =============================================================================

test_warning_category_no_expiration_no_dates if {
	rule := {"value": "some.rule"}
	lib.assert_equal(lib.warning_category(rule), "no_expiration") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_no_expiration_with_past_effective_on if {
	# effectiveOn in past, no effectiveUntil
	rule := {"value": "some.rule", "effectiveOn": "2024-06-01T12:00:00Z"}
	lib.assert_equal(lib.warning_category(rule), "no_expiration") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_no_expiration_empty_strings if {
	rule := {"value": "some.rule", "effectiveOn": "", "effectiveUntil": ""}
	lib.assert_equal(lib.warning_category(rule), "no_expiration") with time_lib.effective_current_time_ns as _now_ns
}

# =============================================================================
# warning_category tests - edge cases
# =============================================================================

test_warning_category_pending_takes_precedence_over_no_expiration if {
	# effectiveOn in future, no effectiveUntil - should be "pending", not "no_expiration"
	rule := {"value": "some.rule", "effectiveOn": "2024-07-15T12:00:00Z"}
	lib.assert_equal(lib.warning_category(rule), "pending") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_with_both_dates_active_and_expiring if {
	# effectiveOn in past, effectiveUntil within threshold
	rule := {
		"value": "some.rule",
		"effectiveOn": "2024-06-01T12:00:00Z",
		"effectiveUntil": "2024-06-25T12:00:00Z",
	}
	lib.assert_equal(lib.warning_category(rule), "expiring") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_pending_with_expired_until if {
	# effectiveOn in future (pending takes precedence), effectiveUntil in past
	rule := {
		"value": "some.rule",
		"effectiveOn": "2024-07-15T12:00:00Z",
		"effectiveUntil": "2024-06-05T12:00:00Z",
	}
	lib.assert_equal(lib.warning_category(rule), "pending") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_pending_with_expiring_until if {
	# effectiveOn in future (pending takes precedence), effectiveUntil expiring
	rule := {
		"value": "some.rule",
		"effectiveOn": "2024-07-15T12:00:00Z",
		"effectiveUntil": "2024-06-25T12:00:00Z",
	}
	lib.assert_equal(lib.warning_category(rule), "pending") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_pending_with_future_until_beyond_threshold if {
	# effectiveOn in future (pending takes precedence), effectiveUntil beyond threshold
	rule := {
		"value": "some.rule",
		"effectiveOn": "2024-07-15T12:00:00Z",
		"effectiveUntil": "2024-08-14T12:00:00Z",
	}
	lib.assert_equal(lib.warning_category(rule), "pending") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_active_with_expired_until if {
	# effectiveOn in past, effectiveUntil in past
	rule := {
		"value": "some.rule",
		"effectiveOn": "2024-06-01T12:00:00Z",
		"effectiveUntil": "2024-06-05T12:00:00Z",
	}
	lib.assert_equal(lib.warning_category(rule), "expired") with time_lib.effective_current_time_ns as _now_ns
}

test_warning_category_active_with_future_until_beyond_threshold if {
	# effectiveOn in past, effectiveUntil beyond threshold (no warning)
	rule := {
		"value": "some.rule",
		"effectiveOn": "2024-06-01T12:00:00Z",
		"effectiveUntil": "2024-08-14T12:00:00Z",
	}

	# Should not produce a category (no warning needed)
	not lib.warning_category(rule) with time_lib.effective_current_time_ns as _now_ns
}
