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

package lib.volatile_config

import rego.v1

import data.lib
import data.lib.time as time_lib

# Get configurable warning threshold from rule_data (default defined in rule_data_defaults)
warning_threshold_days := lib.rule_data("volatile_config_warning_threshold_days")

# Calculate days until a rule expires (returns integer days, can be negative if expired)
days_until_expiration(rule) := days if {
	effective_until := object.get(rule, "effectiveUntil", "")
	effective_until != ""
	until_ns := _parse_date_safe(effective_until)
	until_ns != null
	now_ns := time_lib.effective_current_time_ns
	diff_ns := until_ns - now_ns
	days := floor(diff_ns / (((24 * 60) * 60) * 1000000000))
}

# Check if rule applies to current image - global rule (no image/component constraints)
is_rule_applicable(rule, image_ref, image_digest, component_name) if {
	object.get(rule, "imageRef", "") == ""
	object.get(rule, "imageUrl", "") == ""
	object.get(rule, "imageDigest", "") == ""
	count(object.get(rule, "componentNames", [])) == 0
}

# Check if rule applies - match by imageRef (DEPRECATED: same as imageDigest, both are digests)
is_rule_applicable(rule, image_ref, image_digest, component_name) if {
	rule_image_ref := object.get(rule, "imageRef", "")
	rule_image_ref != ""
	rule_image_ref == image_digest
}

# Check if rule applies - match by imageUrl prefix (URL without tag)
is_rule_applicable(rule, image_ref, image_digest, component_name) if {
	rule_image_url := object.get(rule, "imageUrl", "")
	rule_image_url != ""

	# imageUrl is a URL prefix without tag, match against repo portion of image_ref
	_image_url_matches(rule_image_url, image_ref)
}

# Check if rule applies - match by imageDigest
is_rule_applicable(rule, image_ref, image_digest, component_name) if {
	rule_image_digest := object.get(rule, "imageDigest", "")
	rule_image_digest != ""
	rule_image_digest == image_digest
}

# Check if rule applies - match by componentNames
is_rule_applicable(rule, image_ref, image_digest, component_name) if {
	component_names := object.get(rule, "componentNames", [])
	count(component_names) > 0
	some name in component_names
	name == component_name
}

# Determine warning category - check for invalid dates first
warning_category(rule) := "invalid" if {
	effective_on := object.get(rule, "effectiveOn", "")
	effective_on != ""
	_parse_date_safe(effective_on) == null
}

warning_category(rule) := "invalid" if {
	effective_until := object.get(rule, "effectiveUntil", "")
	effective_until != ""
	_parse_date_safe(effective_until) == null
}

# Pending: effectiveOn is in the future
warning_category(rule) := "pending" if {
	effective_on := object.get(rule, "effectiveOn", "")
	effective_on != ""
	on_ns := _parse_date_safe(effective_on)
	on_ns != null
	now_ns := time_lib.effective_current_time_ns
	on_ns > now_ns
}

# Expired: effectiveUntil is in the past
warning_category(rule) := "expired" if {
	effective_until := object.get(rule, "effectiveUntil", "")
	effective_until != ""
	until_ns := _parse_date_safe(effective_until)
	until_ns != null
	now_ns := time_lib.effective_current_time_ns
	until_ns < now_ns
}

# Expiring: effectiveUntil is within the warning threshold
warning_category(rule) := "expiring" if {
	effective_until := object.get(rule, "effectiveUntil", "")
	effective_until != ""
	until_ns := _parse_date_safe(effective_until)
	until_ns != null
	now_ns := time_lib.effective_current_time_ns
	until_ns >= now_ns # Not yet expired
	days := days_until_expiration(rule)
	days <= warning_threshold_days
}

# No expiration: rule is active (effectiveOn in past or not set) but has no effectiveUntil
warning_category(rule) := "no_expiration" if {
	# No effectiveUntil date set
	object.get(rule, "effectiveUntil", "") == ""

	# And not pending (effectiveOn is in the past or not set)
	effective_on := object.get(rule, "effectiveOn", "")
	_is_active_or_unset(effective_on)
}

# Helper: safely parse RFC3339 date, returns null on failure
_parse_date_safe(date_str) := ns if {
	date_str != ""
	ns := time.parse_rfc3339_ns(date_str)
} else := null

# Helper: check if effectiveOn is active (in the past) or not set
_is_active_or_unset(effective_on) if {
	effective_on == ""
}

_is_active_or_unset(effective_on) if {
	effective_on != ""
	on_ns := _parse_date_safe(effective_on)
	on_ns != null
	now_ns := time_lib.effective_current_time_ns
	on_ns <= now_ns
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
