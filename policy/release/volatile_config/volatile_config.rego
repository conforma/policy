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

#
# METADATA
# title: Volatile Configuration Warnings
# description: >-
#   This package generates warnings for volatile configuration rules that have
#   lifecycle events requiring attention. Volatile config rules can include or
#   exclude policy rules with time-based constraints (effectiveOn/effectiveUntil).
#   Warnings help users proactively manage rule expirations and activations.
#   The optional `reference` field in volatile criteria can be used to link to
#   related documentation (e.g., Jira issues) but is not included in warnings.
#
package volatile_config

import rego.v1

import data.lib

# METADATA
# title: Volatile rule pending activation
# description: >-
#   Generates a warning when a volatile configuration rule has an effectiveOn date
#   in the future, indicating it will become active at that time.
# custom:
#   short_name: pending_rule
#   failure_msg: "Volatile %s rule '%s' is pending activation (effective on: %s)"
#   solution: >-
#     This is informational. The volatile configuration rule will automatically
#     become active on the effective date. No action is required unless you want
#     to adjust the activation timing.
#   collections:
#   - minimal
#   - redhat
#
warn contains result if {
	some rule in _applicable_rules
	lib.warning_category(rule.config) == "pending"
	result := lib.result_helper(
		rego.metadata.chain(),
		[rule.type, rule.config.value, rule.config.effectiveOn],
	)
}

# METADATA
# title: Volatile rule expiring soon
# description: >-
#   Generates a warning when a volatile configuration rule will expire within
#   the configured warning threshold (default 30 days). This provides advance
#   notice to extend or replace the rule before it expires.
# custom:
#   short_name: expiring_rule
#   failure_msg: "Volatile %s rule '%s' expires in %d days (effective until: %s)"
#   solution: >-
#     Review the volatile configuration rule and decide whether to extend its
#     effectiveUntil date or remove it. If the rule is no longer needed, you
#     can safely let it expire.
#   collections:
#   - minimal
#   - redhat
#
warn contains result if {
	some rule in _applicable_rules
	lib.warning_category(rule.config) == "expiring"
	days := lib.days_until_expiration(rule.config)
	result := lib.result_helper(
		rego.metadata.chain(),
		[rule.type, rule.config.value, days, rule.config.effectiveUntil],
	)
}

# METADATA
# title: Volatile rule has no expiration
# description: >-
#   Generates a warning when a volatile configuration rule has no effectiveUntil
#   date set. Rules without expiration dates may accumulate over time and should
#   be periodically reviewed.
# custom:
#   short_name: no_expiration
#   failure_msg: "Volatile %s rule '%s' has no expiration date set"
#   solution: >-
#     Consider adding an effectiveUntil date to the volatile configuration rule
#     to ensure it is reviewed periodically. Permanent exceptions should be
#     documented with justification.
#   collections:
#   - minimal
#   - redhat
#
warn contains result if {
	some rule in _applicable_rules
	lib.warning_category(rule.config) == "no_expiration"
	result := lib.result_helper(
		rego.metadata.chain(),
		[rule.type, rule.config.value],
	)
}

# METADATA
# title: Volatile rule has expired
# description: >-
#   Generates a warning when a volatile configuration rule has passed its
#   effectiveUntil date. Expired rules are no longer active and should be
#   removed from the policy configuration.
# custom:
#   short_name: expired_rule
#   failure_msg: "Volatile %s rule '%s' has expired (effective until: %s)"
#   solution: >-
#     Remove the expired volatile configuration rule from your policy. The rule
#     is no longer having any effect and keeping it may cause confusion.
#   collections:
#   - minimal
#   - redhat
#
warn contains result if {
	some rule in _applicable_rules
	lib.warning_category(rule.config) == "expired"
	result := lib.result_helper(
		rego.metadata.chain(),
		[rule.type, rule.config.value, rule.config.effectiveUntil],
	)
}

# METADATA
# title: Volatile rule has invalid configuration
# description: >-
#   Generates a warning when a volatile configuration rule has invalid date
#   values that cannot be parsed. This indicates a configuration error that
#   should be corrected.
# custom:
#   short_name: invalid_config
#   failure_msg: "Volatile %s rule '%s' has invalid date configuration (effectiveOn: %s, effectiveUntil: %s)"
#   solution: >-
#     Correct the date format in the volatile configuration rule. Dates must be
#     in RFC 3339 format (e.g., "2024-12-31T00:00:00Z").
#   collections:
#   - minimal
#   - redhat
#
warn contains result if {
	some rule in _applicable_rules
	lib.warning_category(rule.config) == "invalid"
	result := lib.result_helper(
		rego.metadata.chain(),
		[
			rule.type,
			rule.config.value,
			object.get(rule.config, "effectiveOn", ""),
			object.get(rule.config, "effectiveUntil", ""),
		],
	)
}

# Collect all applicable volatile config rules from all sources
_applicable_rules contains rule if {
	some source in object.get(input, ["policy_spec", "sources"], [])
	volatile_config := object.get(source, "volatileConfig", {})

	# Process include rules
	some config in object.get(volatile_config, "include", [])
	lib.is_rule_applicable(config, _context)
	rule := {"config": config, "type": "include", "source": object.get(source, "name", "")}
}

_applicable_rules contains rule if {
	some source in object.get(input, ["policy_spec", "sources"], [])
	volatile_config := object.get(source, "volatileConfig", {})

	# Process exclude rules
	some config in object.get(volatile_config, "exclude", [])
	lib.is_rule_applicable(config, _context)
	rule := {"config": config, "type": "exclude", "source": object.get(source, "name", "")}
}

# Get image ref from input
_image_ref := object.get(input, ["image", "ref"], "")

# Extract image digest from ref (e.g., "repo/image@sha256:abc..." -> "sha256:abc...")
_image_digest := digest if {
	_image_ref != ""
	contains(_image_ref, "@")
	parts := split(_image_ref, "@")
	count(parts) == 2
	digest := parts[1]
}

_image_digest := "" if {
	_image_ref == ""
}

_image_digest := "" if {
	_image_ref != ""
	not contains(_image_ref, "@")
}

_image_digest := "" if {
	_image_ref != ""
	contains(_image_ref, "@")
	parts := split(_image_ref, "@")
	count(parts) != 2
}

# Get component name from input
_component_name := object.get(input, "component_name", "")

# Build context object with image and component information
_context := {
	"imageRef": _image_ref,
	"imageDigest": _image_digest,
	"componentName": _component_name,
}
