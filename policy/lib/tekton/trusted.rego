package lib.tekton

import rego.v1

import data.lib.arrays
import data.lib.json as j
import data.lib.time as time_lib

# regal ignore:prefer-package-imports
import data.lib.rule_data as lib_rule_data

# #############################################################################
# TRUSTED TASK LIBRARY
# #############################################################################
#
# This library provides functions for determining whether Tekton Tasks are trusted.
# It supports two systems:
#
# 1. RULES SYSTEM (trusted_task_rules): Pattern-based allow/deny rules.
#    This is the preferred system going forward.
#
# 2. LEGACY SYSTEM (trusted_tasks): Explicit allow list with expiry dates.
#    This system is being phased out.
#
# MIGRATION GUIDE: To remove legacy trusted_tasks support:
#
# 1. Delete the "BEGIN LEGACY SYSTEM" to "END LEGACY SYSTEM" section below
# 2. In the ROUTING LAYER section:
#    - Simplify is_trusted_task to just call is_trusted_task_rules
#    - Simplify untrusted_task_refs to just call untrusted_task_refs_rules
# 3. Remove missing_trusted_tasks_data (or update it)
# 4. Update data_errors to remove trusted_tasks schema validation
#
# #############################################################################

# =============================================================================
# SHARED HELPERS
# Used by both systems. Keep these when removing legacy support.
# =============================================================================

# Returns a subset of tasks that use untagged bundle Task references.
untagged_task_references(tasks) := {task |
	some task in tasks
	ref := task_ref(task)
	ref.bundle
	not ref.tagged
}

# Returns a subset of tasks that use unpinned Task references.
unpinned_task_references(tasks) := {task |
	some task in tasks
	not task_ref(task).pinned
}

# =============================================================================
# DATA PRESENCE HELPERS
# =============================================================================

default missing_trusted_task_rules_data := false

# Returns true if trusted_task_rules data is missing (no allow or deny rules)
missing_trusted_task_rules_data if {
	count(_trusted_task_rules_data.allow) + count(_trusted_task_rules_data.deny) == 0
}

default missing_trusted_tasks_data := false

# Returns true if legacy trusted_tasks data is missing
missing_trusted_tasks_data if {
	count(_trusted_tasks) == 0
}

# Returns true if BOTH systems have no data
missing_all_trusted_tasks_data if {
	missing_trusted_tasks_data
	missing_trusted_task_rules_data
}

# =============================================================================
# ROUTING LAYER
# These functions route to the appropriate system based on data presence.
# Priority: trusted_task_rules > trusted_tasks
# =============================================================================

# Returns true if the task uses a trusted Task reference.
# Routes to the appropriate system based on data presence.
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
is_trusted_task(task, manifests) if {
	not missing_trusted_task_rules_data
	is_trusted_task_rules(task, manifests)
}

is_trusted_task(task, _) if {
	missing_trusted_task_rules_data
	not missing_trusted_tasks_data
	is_trusted_task_legacy(task)
}

# Returns a subset of tasks that do not use a trusted Task reference.
# Routes to the appropriate system based on data presence.
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
untrusted_task_refs(tasks, manifests) := result if {
	not missing_trusted_task_rules_data
	result := untrusted_task_refs_rules(tasks, manifests)
} else := result if {
	result := untrusted_task_refs_legacy(tasks)
}

# =============================================================================
# RULES SYSTEM (trusted_task_rules)
# Pattern-based allow/deny rules for task trust.
# This is the preferred system going forward.
# =============================================================================

# Returns a subset of tasks that are untrusted according to trusted_task_rules.
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
untrusted_task_refs_rules(tasks, manifests) := {task |
	some task in tasks
	not is_trusted_task_rules(task, manifests)
}

# Returns true if the task uses a trusted Task reference according to trusted_task_rules.
# 1. If task matches a deny rule, it's not trusted
# 2. If task matches an allow rule, it's trusted
# 3. Otherwise, it's not trusted
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
is_trusted_task_rules(task, manifests) if {
	ref := task_ref(task)
	not _task_matches_deny_rule(ref, manifests)
	_task_matches_allow_rule(ref, manifests)
}

# Merging in the trusted_task_rules rule data
_trusted_task_rules_data := {
	"allow": array.concat(
		_data_allow_array, # add effective allow rules
		_rule_data_allow_array,
	),
	"deny": array.concat(
		_data_deny_array, # add effective deny rules
		_rule_data_deny_array,
	),
}

# Safely extract allow from data.trusted_task_rules
default _data_allow_array := []

_data_allow_array := data.trusted_task_rules.allow if {
	is_object(data.trusted_task_rules)
}

# Safely extract deny from data.trusted_task_rules
default _data_deny_array := []

_data_deny_array := data.trusted_task_rules.deny if {
	is_object(data.trusted_task_rules)
}

# Safely extract allow from rule_data
default _rule_data_allow_array := []

_rule_data_allow_array := _rule_data_obj.allow if {
	_rule_data_obj := lib_rule_data("trusted_task_rules")
	is_object(_rule_data_obj)
}

# Safely extract deny from rule_data
default _rule_data_deny_array := []

_rule_data_deny_array := _rule_data_obj.deny if {
	_rule_data_obj := lib_rule_data("trusted_task_rules")
	is_object(_rule_data_obj)
}

data_errors contains error if {
	some e in j.validate_schema(
		_trusted_tasks_data,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"patternProperties": {".*": {
				"type": "array",
				"items": {
					"type": "object",
					"properties": {
						"effective_on": {"type": "string"},
						"expires_on": {"type": "string"},
						"ref": {"type": "string"},
					},
					"required": ["ref"],
					"additionalProperties": false,
				},
				"minItems": 1,
			}},
		},
	)

	error := {
		"message": sprintf("trusted_tasks data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

data_errors contains error if {
	some task, refs in _trusted_tasks_data
	some i, ref in refs
	not time.parse_rfc3339_ns(ref.effective_on)
	error := {
		"message": sprintf(
			"trusted_tasks.%s[%d].effective_on is not valid RFC3339 format: %q",
			[task, i, ref.effective_on],
		),
		"severity": "failure",
	}
}

data_errors contains error if {
	some task, refs in _trusted_tasks_data
	some i, ref in refs
	not time.parse_rfc3339_ns(ref.expires_on)
	error := {
		"message": sprintf(
			"trusted_tasks.%s[%d].expires_on is not valid RFC3339 format: %q",
			[task, i, ref.expires_on],
		),
		"severity": "failure",
	}
}

data_errors contains error if {
	some error in j.validate_schema(
		{"task_expiry_warning_days": lib_rule_data("task_expiry_warning_days")},
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"properties": {"task_expiry_warning_days": {
				"type": "integer",
				"minimum": 0,
			}},
		},
	)
}

# Validate trusted_task_rules data format using the schema defined in
# trusted_tasks/trusted_task_rules.schema.json
# Skip validation if trusted_task_rules is not provided (null or empty list []).
# lib_rule_data returns [] when a key is not found, so we only validate when
# the value is actually an object (the expected type).
data_errors contains error if {
	# Only validate if rule_data contains an object (skip when it's [] or not provided)
	rule_data_rules := lib_rule_data("trusted_task_rules")
	is_object(rule_data_rules)
	some e in j.validate_schema(rule_data_rules, _trusted_task_rules_schema)
	error := {
		"message": sprintf("trusted_task_rules data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

# Filter allow rules to only include those that are currently effective (not in the future)
_effective_allow_rules := [rule |
	some rule in _trusted_task_rules_data.allow
	_rule_is_effective(rule)
]

# Filter deny rules to only include those that are currently effective (not in the future)
_effective_deny_rules := [rule |
	some rule in _trusted_task_rules_data.deny
	_rule_is_effective(rule)
]

# Filter deny rules to only include those that will become effective in the future
future_deny_rules := [rule |
	some rule in _trusted_task_rules_data.deny
	_rule_is_future(rule)
]

# Returns true if a rule has a future effective_on date
_rule_is_future(rule) if {
	"effective_on" in object.keys(rule)
	effective_date := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [rule.effective_on]))
	effective_date > time_lib.effective_current_time_ns
}

# Returns future deny rules that would match the given task
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
future_deny_rules_for_task(task, manifests) := matching_rules if {
	ref := task_ref(task)
	matching_rules := [rule |
		some rule in future_deny_rules
		_pattern_matches(ref.key, rule.pattern)
		_version_satisfies_any_rule_constraints(ref, rule, manifests)
	]
}

# Returns true if a rule is currently effective (either has no effective_on date, or the date is not in the future)
_rule_is_effective(rule) if {
	not "effective_on" in object.keys(rule)
} else if {
	effective_date := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [rule.effective_on]))
	effective_date <= time_lib.effective_current_time_ns
}

# Returns true if the task reference matches a deny rule pattern and version constraints (if specified)
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
_task_matches_deny_rule(ref, manifests) if {
	some rule in _effective_deny_rules
	_pattern_matches(ref.key, rule.pattern)
	_version_satisfies_any_rule_constraints(ref, rule, manifests)
}

# Returns a list of patterns from deny rules that match the task, or an empty list if no deny rules match.
# This only applies to trusted_task_rules (not legacy trusted_tasks).
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
denying_pattern(task, manifests) := [rule.pattern |
	ref := task_ref(task)
	some rule in _effective_deny_rules
	_pattern_matches(ref.key, rule.pattern)
	_version_satisfies_any_rule_constraints(ref, rule, manifests)
]

# Returns the reason why a task reference was denied, or nothing if the task is trusted.
# There are three ways a task can be denied:
# 1. It matches a deny rule pattern (type: "deny_rule", pattern: list of matching deny
#    patterns, messages: list of messages)
# 2. It doesn't match any allow rule pattern (type: "not_allowed", pattern: empty list)
# 3. No effective allow rules exist but raw rules are defined (type: "no_effective_rules")
# This only applies to trusted_task_rules (not legacy trusted_tasks).
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
denial_reason(task, manifests) := reason if {
	deny_info := _denying_rules_info(task, manifests)
	count(deny_info.patterns) > 0
	reason := {
		"type": "deny_rule",
		"pattern": deny_info.patterns,
		"messages": deny_info.messages,
	}
} else := reason if {
	# Case 2: Doesn't match any allow rule
	# Only applies if there are effective allow rules defined
	ref := task_ref(task)
	count(_effective_allow_rules) > 0
	not _task_matches_allow_rule(ref, manifests)
	not _task_matches_deny_rule(ref, manifests)

	reason := {
		"type": "not_allowed",
		"pattern": [],
		"messages": [],
	}
} else := reason if {
	# Case 3: No effective allow rules exist but raw rules are defined
	# This happens when all allow rules have future effective_on dates
	count(_effective_allow_rules) == 0
	count(_trusted_task_rules_data.allow) > 0

	reason := {
		"type": "no_effective_rules",
		"pattern": [],
		"messages": [],
	}
}

# Returns patterns and messages from deny rules that match the task
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
_denying_rules_info(task, manifests) := {"patterns": patterns, "messages": messages} if {
	ref := task_ref(task)

	# Get all matching deny rules
	matching_rules := [rule |
		some rule in _effective_deny_rules
		_pattern_matches(ref.key, rule.pattern)
		_version_satisfies_any_rule_constraints(ref, rule, manifests)
	]

	patterns := [rule.pattern | some rule in matching_rules]
	messages := [rule.message | some rule in matching_rules; "message" in object.keys(rule)]
}

# Returns true if the task reference matches an allow rule pattern and version constraints (if specified)
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
_task_matches_allow_rule(ref, manifests) if {
	some rule in _effective_allow_rules
	_pattern_matches(ref.key, rule.pattern)
	_version_satisfies_all_rule_constraints(ref, rule, manifests)
}

# Converts a wildcard pattern to a regex pattern and checks if the key matches
# Wildcards (*) are converted to .* in regex
_pattern_matches(key, pattern) if {
	regex_pattern := regex.replace(pattern, `\*`, ".*")
	regex.match(regex_pattern, key)
}

# Schema for trusted_task_rules as defined in trusted_tasks/trusted_task_rules.schema.json
# This schema validates the rule-based trusted tasks configuration (ADR 53)
_trusted_task_rules_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"$id": "https://konflux.io/schemas/trusted_task_rules.json",
	"title": "Trusted Task Rules Schema",
	"description": "Schema for trusted_task_rules configuration as defined in ADR 53",
	"type": "object",
	"properties": {
		"allow": {
			"type": "array",
			"description": "Rules that allow tasks matching the pattern",
			"items": {
				"type": "object",
				"required": ["name", "pattern"],
				"properties": {
					"name": {
						"type": "string",
						"description": "Human-readable name for the rule",
					},
					"pattern": {
						"type": "string",
						# regal ignore:line-length
						"description": "URL pattern to match task references. Must not include version tags (e.g., 'oci://quay.io/konflux-ci/tekton-catalog/*' not 'oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4*'). Supports wildcards (*).",
						"pattern": "^(oci://|git\\+)",
					},
					"effective_on": {
						"type": "string",
						"format": "date",
						# regal ignore:line-length
						"description": "Date when this rule becomes effective (e.g., '2025-02-01'). Rules with future effective_on dates are not considered. If omitted, rule is effective immediately.",
					},
					"versions": {
						"type": "array",
						"description": "List of version constraints to match only specific versions of the task",
						"items": {
							"type": "string",
							"description": "Version constraint (e.g., '>=2.1', '<1.2.3')",
						},
					},
				},
				"additionalProperties": true,
			},
			"default": [],
		},
		"deny": {
			"type": "array",
			"description": "Rules that deny tasks matching the pattern. Deny rules take precedence over allow rules.",
			"items": {
				"type": "object",
				"required": ["name", "pattern"],
				"properties": {
					"name": {
						"type": "string",
						"description": "Human-readable name for the rule",
					},
					"pattern": {
						"type": "string",
						# regal ignore:line-length
						"description": "URL pattern to match task references. Must not include version tags (e.g., 'oci://quay.io/konflux-ci/tekton-catalog/task-buildah*' not 'oci://quay.io/konflux-ci/tekton-catalog/task-buildah:0.4*'). Supports wildcards (*).",
						"pattern": "^(oci://|git\\+)",
					},
					"effective_on": {
						"type": "string",
						"format": "date",
						# regal ignore:line-length
						"description": "Date when this rule becomes effective (e.g., '2025-11-15'). Rules with future effective_on dates are not considered. If omitted, rule is effective immediately.",
					},
					"message": {
						"type": "string",
						"description": "User-visible message explaining why the task is denied (e.g., deprecation notice)",
					},
					"versions": {
						"type": "array",
						"description": "List of version constraints to match only specific versions of the task",
						"items": {
							"type": "string",
							"description": "Version constraint (e.g., '>=2.1', '<1.2.3')",
						},
					},
				},
				"additionalProperties": true,
			},
			"default": [],
		},
	},
	"additionalProperties": false,
}

# Returns true if the task reference version satisfies ALL semver constraints in the rule.
# This is intended for use in allow rules, where the rule is effective if all constraints match.
# Supports constraints like: >=v2, <3, >3.1.0, <v4.2, >=1.2.3
# Returns true if rule has no "versions" field
# Returns false if versions field exists but no manifest version is found (don't allow by default for security)
# Returns true if task version satisfies all constraints
# Returns false otherwise
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
_version_satisfies_all_rule_constraints(ref, rule, manifests) if {
	not "versions" in object.keys(rule)
} else if {
	# If versions field exists, manifest version must be found
	manifest_version := _get_manifest_version_annotation(ref, manifests)
	version := _normalize_version(manifest_version)
	semver.is_valid(version)

	constraints := rule.versions

	# Task version must satisfy ALL constraints
	every constraint in constraints {
		constraint_version := _normalize_version(constraint)
		semver.is_valid(constraint_version)

		result := semver.compare(version, constraint_version)
		_result_satisfies_operator(result, constraint)
	}
}

# Returns true if the task reference version satisfies AT LEAST ONE semver constraint in the rule.
# This is intended for use in deny rules, where the rule is effective if at least one constraint match.
# Supports constraints like: >=v2, <3, >3.1.0, <v4.2, >=1.2.3
# Returns true if rule has no "versions" field
# Returns true if versions field exists but no manifest version is found (deny by default for security)
# Returns true if task version satisfies at least one constraint
# Returns false otherwise
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
_version_satisfies_any_rule_constraints(ref, rule, manifests) if {
	not "versions" in object.keys(rule)
} else if {
	# If versions field exists but no manifest version found, deny the task (return true)
	"versions" in object.keys(rule)
	not _get_manifest_version_annotation(ref, manifests)
} else if {
	manifest_version := _get_manifest_version_annotation(ref, manifests)
	version := _normalize_version(manifest_version)
	not semver.is_valid(version)
} else if {
	manifest_version := _get_manifest_version_annotation(ref, manifests)
	version := _normalize_version(manifest_version)
	semver.is_valid(version)

	constraints := rule.versions

	# Task version must satisfy at least one constraint
	some constraint in constraints
	constraint_version := _normalize_version(constraint)
	semver.is_valid(constraint_version)

	result := semver.compare(version, constraint_version)
	_result_satisfies_operator(result, constraint)
}

# Returns normalized semver (e.g: ">=v1.2" -> "1.2.0"; "v1.0" -> "1.0.0")
# Strips operators (>=, >, <=, <), 'v' prefix, and normalizes to major.minor.patch format
_normalize_version(to_normalize) := result if {
	__version := trim_prefix(to_normalize, "<")
	_version := trim_prefix(__version, ">")
	version := trim_prefix(_version, "=")

	trimmed := trim_prefix(version, "v")
	parts := split(trimmed, ".")

	# Normalize to major.minor.patch (default missing components to "0")
	major := parts[0]
	minor := _get_version_component(parts, 1)
	patch := _get_version_component(parts, 2)

	result := concat(".", [major, minor, patch])
}

# Returns version component at index, or "0" if not present
_get_version_component(parts, idx) := parts[idx] if {
	count(parts) > idx
} else := "0"

# Returns true if semver.compare result satisfies the constraint operator
# result is -1 (less), 0 (equal), or 1 (greater)
_result_satisfies_operator(result, constraint) if {
	startswith(constraint, ">=")
	result >= 0
} else if {
	startswith(constraint, ">")
	not startswith(constraint, ">=")
	result > 0
} else if {
	startswith(constraint, "<=")
	result <= 0
} else if {
	startswith(constraint, "<")
	not startswith(constraint, "<=")
	result < 0
} else := false

# Returns the version annotation from the manifest for a bundle reference.
# manifests is a map of bundle_ref -> manifest from ec.oci.image_manifests
_get_manifest_version_annotation(ref, manifests) := version if {
	task_manifest := manifests[ref.bundle]
	annotations := object.get(task_manifest, "annotations", {})
	version := annotations["org.opencontainers.image.version"]
	version != null
}

# =============================================================================
# BEGIN LEGACY SYSTEM (trusted_tasks)
# Explicit allow list with expiry dates.
# DELETE THIS ENTIRE SECTION when removing legacy support.
# =============================================================================

# Returns a subset of tasks that are untrusted according to the legacy trusted_tasks data.
untrusted_task_refs_legacy(tasks) := {task |
	some task in tasks
	not is_trusted_task_legacy(task)
}

# Returns true if the task uses a trusted Task reference from trusted_tasks data.
is_trusted_task_legacy(task) if {
	ref := task_ref(task)
	some record in trusted_task_records(ref.key)
	record.ref == ref.pinned_ref
}

# Returns records from trusted_tasks that match the given reference key
trusted_task_records(ref_key) := records if {
	records := _trusted_tasks[ref_key]
	count(records) > 0
} else := records if {
	startswith(ref_key, "oci://")
	records := [match |
		some key, matches in _trusted_tasks
		short_key := regex.replace(key, `:[0-9.]+$`, "")
		ref_key == short_key
		some match in matches
	]
} else := records if {
	records := []
}

# Returns the latest trusted reference for a task (for upgrade suggestions)
latest_trusted_ref(task) := trusted_task_ref if {
	ref := task_ref(task)
	records := trusted_task_records(ref.key)
	count(records) > 0
	trusted_task_ref = records[0].ref
}

default task_expiry_warnings_after := 0

# Returns the grace period threshold for expiry warnings
task_expiry_warnings_after := grace if {
	grace_period_days := lib_rule_data("task_expiry_warning_days")
	grace_period_days > 0
	grace := time.add_date(
		time_lib.effective_current_time_ns, 0, 0,
		grace_period_days,
	)
}

# Returns the expiry time if task is expiring within the warning period
expiry_of(task) := expires if {
	expires := _task_expires_on(task)
	expires > task_expiry_warnings_after
}

# Returns the expiry timestamp for a task from trusted_tasks data
_task_expires_on(task) := expires if {
	ref := task_ref(task)
	records := _trusted_tasks[ref.key]

	matching_records := [r |
		some r in records
		r.ref == ref.pinned_ref
	]

	record := matching_records[0]
	expires = time.parse_rfc3339_ns(record.expires_on)
}

# Filters out expired records from trusted_tasks
_unexpired_records(records) := all_unexpired if {
	never_expires := [record |
		some record in records
		not "expires_on" in object.keys(record)
	]

	future_expires := [record |
		some record in records
		expires := time.parse_rfc3339_ns(record.expires_on)
		expires > time_lib.effective_current_time_ns
	]
	future_expires_sorted := array.reverse(arrays.sort_by("expires_on", future_expires))

	all_unexpired := array.concat(never_expires, future_expires_sorted)
}

# Provides access to trusted_tasks data with expired records filtered out
_trusted_tasks[key] := pruned_records if {
	some key, records in _trusted_tasks_data
	pruned_records := _unexpired_records(records)
}

# Merges trusted_tasks from data and rule_data sources
_trusted_tasks_data := object.union(data.trusted_tasks, lib_rule_data("trusted_tasks"))

# =============================================================================
# END LEGACY SYSTEM
# =============================================================================
