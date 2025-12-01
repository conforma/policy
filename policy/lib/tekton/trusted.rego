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

# Returns if the list of trusted Tasks are missing
default missing_trusted_tasks_data := false

missing_trusted_tasks_data if {
	count(_trusted_tasks) == 0
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

# Returns a subset of tasks that do not use a trusted Task reference.
untrusted_task_refs(tasks) := {task |
	some task in tasks
	not is_trusted_task(task)
}

# Returns true if the task uses a trusted Task reference.
is_trusted_task(task) if {
	ref := task_ref(task)

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

# Returns the date in epoch nanoseconds when the task expires, or nothing if it
# hasn't expired yet.
_task_expires_on(task) := expires if {
	ref := task_ref(task)
	records := trusted_task_records(ref.key)

	matching_records := [r |
		some r in records
		r.ref == ref.pinned_ref
	]

	# Avoid an "eval_conflict_error: functions must not produce multiple
	# outputs..." error if the data has duplicate records for this ref
	record := matching_records[0]

	expires = time.parse_rfc3339_ns(record.expires_on)
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
	trusted_task_rules_data := lib_rule_data("trusted_task_rules")
	is_object(trusted_task_rules_data) # Only validate if it's an object (skip null and [])
	some e in j.validate_schema(trusted_task_rules_data, _trusted_task_rules_schema)
	error := {
		"message": sprintf("trusted_task_rules data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
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
