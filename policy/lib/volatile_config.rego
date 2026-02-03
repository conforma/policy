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

# Library functions for evaluating volatile configuration rules and determining
# warning categories based on lifecycle events (pending activation, expiring soon,
# no expiration, expired, invalid dates).

package lib

import rego.v1

import data.lib.time as time_lib

# Get configurable warning threshold from rule_data (default defined in rule_data_defaults)
warning_threshold_days := rule_data("volatile_config_warning_threshold_days")

# Nanoseconds per day constant
_ns_per_day := 86400000000000

# Calculate days until a rule expires (returns integer days, can be negative if expired)
days_until_expiration(rule) := days if {
	until_ns := _get_effective_until_ns(rule)
	now_ns := time_lib.effective_current_time_ns
	diff_ns := until_ns - now_ns
	days := floor(diff_ns / _ns_per_day)
}

# Check if rule applies to current image/component
# context is an object with optional fields: imageRef, imageDigest, componentName
# Returns true if the rule matches based on any of the following criteria:
# - Global rule (no image/component constraints)
# - Match by imageRef (DEPRECATED: same as imageDigest, both are digests)
# - Match by imageUrl prefix (URL without tag)
# - Match by imageDigest
# - Match by componentNames
is_rule_applicable(rule, _) if {
	# Global rule: no constraints specified
	object.get(rule, "imageRef", "") == ""
	object.get(rule, "imageUrl", "") == ""
	object.get(rule, "imageDigest", "") == ""
	count(object.get(rule, "componentNames", [])) == 0
}

is_rule_applicable(rule, context) if {
	# Match by imageRef (DEPRECATED: same as imageDigest, both are digests)
	rule_image_ref := object.get(rule, "imageRef", "")
	rule_image_ref != ""
	context_digest := object.get(context, "imageDigest", "")
	rule_image_ref == context_digest
}

is_rule_applicable(rule, context) if {
	# Match by imageUrl prefix (URL without tag)
	rule_image_url := object.get(rule, "imageUrl", "")
	rule_image_url != ""
	context_image_ref := object.get(context, "imageRef", "")
	_image_url_matches(rule_image_url, context_image_ref)
}

is_rule_applicable(rule, context) if {
	# Match by imageDigest
	rule_image_digest := object.get(rule, "imageDigest", "")
	rule_image_digest != ""
	context_digest := object.get(context, "imageDigest", "")
	rule_image_digest == context_digest
}

is_rule_applicable(rule, context) if {
	# Match by componentNames
	component_names := object.get(rule, "componentNames", [])
	count(component_names) > 0
	context_component_name := object.get(context, "componentName", "")
	some name in component_names
	name == context_component_name
}

# Determine warning category - check for invalid dates first
warning_category(rule) := "invalid" if {
	_is_date_invalid(_get_effective_on(rule))
}

warning_category(rule) := "invalid" if {
	_is_date_invalid(_get_effective_until(rule))
}

# Pending: effectiveOn is in the future
warning_category(rule) := "pending" if {
	_is_effective_on_in_future(rule)
	_is_effective_until_valid_or_empty(rule)
}

# Expired: effectiveUntil is in the past
warning_category(rule) := "expired" if {
	_is_effective_until_expired(rule)
	_is_effective_on_valid_and_not_future(rule)
}

# Expiring: effectiveUntil is within the warning threshold
warning_category(rule) := "expiring" if {
	_is_effective_until_expiring(rule)
	_is_effective_on_valid_and_not_future(rule)
}

# No expiration: rule is active (effectiveOn in past or not set) but has no effectiveUntil
warning_category(rule) := "no_expiration" if {
	_get_effective_until(rule) == ""
	_is_effective_on_active_or_unset(rule)
}

# =============================================================================
# Helper functions for date extraction and validation
# =============================================================================

# Extract effectiveOn date string from rule
_get_effective_on(rule) := object.get(rule, "effectiveOn", "")

# Extract effectiveUntil date string from rule
_get_effective_until(rule) := object.get(rule, "effectiveUntil", "")

# Safely parse RFC3339 date, undefined on failure
_parse_date_safe(date_str) := ns if {
	date_str != ""
	ns := time.parse_rfc3339_ns(date_str)
}

# Check if a date string is invalid (non-empty but unparseable)
# Empty strings are considered valid (not set, not invalid)
_is_date_invalid(date_str) if {
	date_str != ""
	not _parse_date_safe(date_str)
}

# Get effectiveOn as nanoseconds, undefined if invalid or empty
_get_effective_on_ns(rule) := _parse_date_safe(_get_effective_on(rule))

# Get effectiveUntil as nanoseconds, undefined if invalid or empty
_get_effective_until_ns(rule) := _parse_date_safe(_get_effective_until(rule))

# Check if effectiveOn is in the future
_is_effective_on_in_future(rule) if {
	on_ns := _get_effective_on_ns(rule)
	now_ns := time_lib.effective_current_time_ns
	on_ns > now_ns
}

# Check if effectiveOn is active (in the past) or not set
_is_effective_on_active_or_unset(rule) if {
	_get_effective_on(rule) == ""
} else if {
	on_ns := _get_effective_on_ns(rule)
	now_ns := time_lib.effective_current_time_ns
	on_ns <= now_ns
}

# Check if effectiveOn is valid (if set) and not in the future
_is_effective_on_valid_and_not_future(rule) if {
	_get_effective_on(rule) == ""
} else if {
	on_ns := _get_effective_on_ns(rule)
	now_ns := time_lib.effective_current_time_ns
	on_ns <= now_ns
}

# Check if effectiveUntil is valid (if set) or empty
_is_effective_until_valid_or_empty(rule) if {
	_get_effective_until(rule) == ""
} else if {
	_get_effective_until_ns(rule)
}

# Check if effectiveUntil is expired (in the past)
_is_effective_until_expired(rule) if {
	until_ns := _get_effective_until_ns(rule)
	now_ns := time_lib.effective_current_time_ns
	until_ns < now_ns
}

# Check if effectiveUntil is expiring (within warning threshold)
_is_effective_until_expiring(rule) if {
	until_ns := _get_effective_until_ns(rule)
	now_ns := time_lib.effective_current_time_ns
	until_ns >= now_ns
	days := days_until_expiration(rule)
	days <= warning_threshold_days
}

# Helper: check if imageUrl matches the image reference
# imageUrl is a URL pattern without tag (e.g., "quay.io/redhat/myimage")
# image_ref may include tag and/or digest (e.g., "quay.io/redhat/myimage:v1@sha256:...")
_image_url_matches(url_pattern, image_ref) if {
	# Extract the repo portion (before any : or @)
	ref_without_digest := split(image_ref, "@")[0]
	ref_without_tag := split(ref_without_digest, ":")[0]

	# Check if pattern matches exactly
	ref_without_tag == url_pattern
}

_image_url_matches(url_pattern, image_ref) if {
	ref_without_digest := split(image_ref, "@")[0]
	ref_without_tag := split(ref_without_digest, ":")[0]

	# Also allow prefix matching for broader scopes (e.g., "quay.io/redhat" matches "quay.io/redhat/myimage")
	startswith(ref_without_tag, sprintf("%s/", [url_pattern]))
}
