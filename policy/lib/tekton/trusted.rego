package lib.tekton

import rego.v1

import data.lib.arrays
import data.lib.json as j
import data.lib.time as time_lib

# regal ignore:prefer-package-imports
import data.lib.rule_data as lib_rule_data

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

default missing_trusted_task_rules_data := false

# returns true if the trusted_task_rules data is missing
missing_trusted_task_rules_data if {
	count(_trusted_task_rules_data.allow) + count(_trusted_task_rules_data.deny) == 0
}

default missing_trusted_tasks_data := false

# Returns if the list of trusted Tasks are missing
# This is true only when BOTH legacy trusted_tasks AND trusted_task_rules are empty
missing_trusted_tasks_data if {
	# Check if both legacy trusted_tasks and trusted_task_rules are empty
	count(_trusted_tasks) == 0
}

missing_all_trusted_tasks_data if {
	# Check if both legacy trusted_tasks and trusted_task_rules are empty
	missing_trusted_tasks_data
	missing_trusted_task_rules_data
}

default task_expiry_warnings_after := 0

task_expiry_warnings_after := grace if {
	grace_period_days := lib_rule_data("task_expiry_warning_days")
	grace_period_days > 0
	grace := time.add_date(
		time_lib.effective_current_time_ns, 0, 0,
		grace_period_days,
	)
}

# Returns the epoch time in nanoseconds of the time when the Task expires, or
# nothing if Task is not set to expire currently.
expiry_of(task) := expires if {
	expires := _task_expires_on(task)

	# only report if the task is expiring within task_expiry_warning_days days
	expires > task_expiry_warnings_after
}

# Returns the date in epoch nanoseconds when the task expires, or nothing if it
# hasn't expired yet.
_task_expires_on(task) := expires if {
	ref := task_ref(task)
	records := _trusted_tasks[ref.key]

	matching_records := [r |
		some r in records
		r.ref == ref.pinned_ref
	]

	# Avoid an "eval_conflict_error: functions must not produce multiple
	# outputs..." error if the data has duplicate records for this ref
	record := matching_records[0]

	expires = time.parse_rfc3339_ns(record.expires_on)
}

# Returns a subset of tasks that do not use a trusted Task reference.
untrusted_task_refs(tasks) := {task |
	some task in tasks
	not is_trusted_task(task)
}

# Returns true if the task uses a trusted Task reference.
# Trusted_task_rules take precedence over trusted_tasks:
# 1. If task matches a deny rule, it's not trusted
# 2. If task matches an allow rule, it's trusted
# 3. Otherwise, fall back to trusted_task_records (legacy trusted_tasks)
is_trusted_task(task) if {
	ref := task_ref(task)

	# First check deny rules (they take precedence)
	not _task_matches_deny_rule(ref)

	# Then check allow rules
	_task_matches_allow_rule(ref)
} else if {
	ref := task_ref(task)

	# If no deny rule matches, check allow rules
	not _task_matches_deny_rule(ref)
	not _task_matches_allow_rule(ref)

	# Fall back to legacy trusted_task_records
	some record in trusted_task_records(ref.key)

	# A trusted task reference is one that is recorded in the trusted tasks data, this is done by
	# matching its pinned reference; note no care is given to the expiry or freshness since expired
	# records have already been filtered out.
	record.ref == ref.pinned_ref
}

trusted_task_records(ref_key) := records if {
	# the reference key matches exactly the key in the trusted tasks set
	records := _trusted_tasks[ref_key]
	count(records) > 0
} else := records if {
	startswith(ref_key, "oci://") # only for oci refs
	records := [match |
		some key, matches in _trusted_tasks
		short_key := regex.replace(key, `:[0-9.]+$`, "")
		ref_key == short_key
		some match in matches
	]
} else := records if {
	# If the key is not found, default to an empty list
	records := []
}

latest_trusted_ref(task) := trusted_task_ref if {
	ref := task_ref(task)
	records := trusted_task_records(ref.key)
	count(records) > 0
	trusted_task_ref = records[0].ref
}

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

# _trusted_tasks provides a safe way to access the list of trusted tasks. It prevents a policy rule
# from incorrectly not evaluating due to missing data. It also removes stale records.
_trusted_tasks[key] := pruned_records if {
	some key, records in _trusted_tasks_data
	pruned_records := _unexpired_records(records)
}

# Merging in the trusted_tasks rule data makes it easier for users to customize their trusted tasks
_trusted_tasks_data := object.union(data.trusted_tasks, lib_rule_data("trusted_tasks"))

# Merging in the trusted_task_rules rule data makes it easier for users to customize their trusted task rules
# Note: We need to merge arrays, not use object.union which would overwrite them
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
	data.trusted_task_rules
}

# Safely extract deny from data.trusted_task_rules
default _data_deny_array := []

_data_deny_array := data.trusted_task_rules.deny if {
	data.trusted_task_rules
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

# Returns true if a rule is currently effective (either has no effective_on date, or the date is not in the future)
_rule_is_effective(rule) if {
	not "effective_on" in object.keys(rule)
} else if {
	effective_date := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [rule.effective_on]))
	effective_date <= time_lib.effective_current_time_ns
}

# Returns true if the task reference matches a deny rule pattern and version constraints (if specified)
_task_matches_deny_rule(ref) if {
	some rule in _effective_deny_rules
	_pattern_matches(ref.key, rule.pattern)
	_version_constraints_match(ref, rule)
}

# Returns a list of patterns from deny rules that match the task, or an empty list if no deny rules match.
# This only applies to trusted_task_rules (not legacy trusted_tasks).
denying_pattern(task) := [rule.pattern |
	ref := task_ref(task)
	some rule in _effective_deny_rules
	_pattern_matches(ref.key, rule.pattern)
	_version_constraints_match(ref, rule)
]

# Returns the reason why a task reference was denied, or nothing if the task is trusted.
# There are two ways a task can be denied:
# 1. It matches a deny rule pattern (type: "deny_rule", pattern: list of matching deny
#    patterns, messages: list of messages)
# 2. It doesn't match any allow rule pattern (type: "not_allowed", pattern: empty list)
# This only applies to trusted_task_rules (not legacy trusted_tasks).
# Note: If there are no allow rules defined, this function returns nothing (we don't check legacy).
denial_reason(task) := reason if {
	deny_info := _denying_rules_info(task)
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
	not _task_matches_allow_rule(ref)
	not _task_matches_deny_rule(ref)

	reason := {
		"type": "not_allowed",
		"pattern": [],
		"messages": [],
	}
}

# Returns patterns and messages from deny rules that match the task
_denying_rules_info(task) := {"patterns": patterns, "messages": messages} if {
	ref := task_ref(task)

	# Get all matching deny rules
	matching_rules := [rule |
		some rule in _effective_deny_rules
		_pattern_matches(ref.key, rule.pattern)
		_version_constraints_match(ref, rule)
	]

	patterns := [rule.pattern | some rule in matching_rules]
	messages := [rule.message | some rule in matching_rules; "message" in object.keys(rule)]
}

# Returns true if the task reference matches an allow rule pattern and version constraints (if specified)
_task_matches_allow_rule(ref) if {
	some rule in _effective_allow_rules
	_pattern_matches(ref.key, rule.pattern)
	_version_constraints_match(ref, rule)
}

# Converts a wildcard pattern to a regex pattern and checks if the key matches
# Wildcards (*) are converted to .* in regex
_pattern_matches(key, pattern) if {
	regex_pattern := regex.replace(pattern, `\*`, ".*")
	regex.match(regex_pattern, key)
}

# Returns true if version constraints match (or if no version constraints are specified)
# Version constraints are optional - if not specified, the rule matches regardless of version
_version_constraints_match(ref, rule) if {
	not "versions" in object.keys(rule)
} else if {
	# Extract version/tag from the reference
	version := _extract_version_from_ref(ref)
	version != ""

	# Version must match at least one constraint
	some constraint in rule.versions
	_semver_constraint_matches(version, constraint)
}

# Extract version/tag from task reference
# For OCI bundles, this is the tagged_ref (e.g., "0.4" from "oci://registry.io/task:0.4")
# For git references, there's no version tag, so return empty string
_extract_version_from_ref(ref) := ref.tagged_ref if {
	"tagged_ref" in object.keys(ref)
	ref.tagged_ref != ""
} else := ""

# Check if a version matches a semver constraint
# TODO: Implement proper semver constraint matching
# For now, if version looks like semver, we'll accept it
# This is a placeholder that should be replaced with proper semver constraint evaluation
# Note: Non-semver tags never match version constraints (per schema)
# regal ignore:argument-always-wildcard
_semver_constraint_matches(version, _) if {
	_is_semver_like(version)
}

# Check if a version string looks like semver (e.g., "0.4.0", "1.2.3", "v0.5.0")
_is_semver_like(version) if {
	regex.match(`^v?[0-9]+\.[0-9]+(\.[0-9]+)?(-[a-zA-Z0-9-]+)?(\+[a-zA-Z0-9-]+)?$`, version)
}

# _trusted_task_rules_data provides safe access to trusted_task_rules rule data. It defaults to an
# empty structure if the data is not provided, preventing policy rules from incorrectly not
# evaluating due to missing data.

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
					"expires_on": {
						"type": "string",
						"format": "date",
						# regal ignore:line-length
						"description": "Date when this rule expires (e.g., '2025-02-01'). Rules with future expires_on dates are not considered. If omitted, rule never expires.",
					},
					"versions": {
						"type": "array",
						# regal ignore:line-length
						"description": "Version constraints to apply. Only tasks matching these version constraints are allowed. Non-semver tags never match version constraints.",
						"items": {
							"type": "string",
							"description": "Version constraint using semver syntax (e.g., '<0.5', '>=2,<2.1.0')",
						},
						"minItems": 1,
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
						# regal ignore:line-length
						"description": "Version constraints to apply. Only tasks matching these version constraints are denied. Non-semver tags never match version constraints.",
						"items": {
							"type": "string",
							"description": "Version constraint using semver syntax (e.g., '<0.5', '>=2,<2.1.0')",
						},
						"minItems": 1,
					},
				},
				"additionalProperties": true,
			},
			"default": [],
		},
	},
	"additionalProperties": false,
}
