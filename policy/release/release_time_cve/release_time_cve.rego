# METADATA
# title: Release-time CVE checks
# description: >-
#   Check for fixed CRITICAL and IMPORTANT CVEs using CVE scan data produced at release-time
#   by tasks in the collector pipeline, independently of the CVE scan report in build
#   provenance, which is presumably older and hence less current than the release-time scan.
package release_time_cve

import rego.v1

import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data
import data.lib.time as lib_time

# METADATA
# title: CVEs past their release-time grace period
# description: >-
#   Block releases containing CVEs in RHSA advisories after the severity-specific
#   grace period. Without configuration the defaults are 30 days for CRITICAL
#   and 60 for IMPORTANT. If `release_time_cve_leeway` is configured,
#   omitted severities have no grace period (0 days).
#   Advisory data is expected in the `collector_data` runtime data key under `RHSA`.
#   Only advisories listing input.component_name in their components apply.
# custom:
#   short_name: advisory_grace_period_expired
#   failure_msg: '%s CVE %s in advisory %s was released on %s (grace period: %d days)'
#   solution: Remediate the CVE before releasing the affected component.
#   pipeline_intention:
#   # Expected to run only in release pipeline
#   - release
#   - production
#   - staging
#   collections:
#   - redhat
#   - redhat_security
#   # Roll this out initially as a warning. Expect to change this date earlier
#   # once we are confident everything is working as expected
#   effective_on: 2027-07-01T00:00:00Z
#
deny contains result if {
	metadata.pipeline_intention_match(rego.metadata.chain())

	rhsa := object.get(rule_data.runtime_data("collector_data"), "RHSA", {})
	some severity, grace_days in _grace_period_days
	some advisory in rhsa[severity]
	input.component_name in advisory.components
	some cve in advisory.cves
	is_string(cve)
	cve != ""

	within_grace_period := _within_grace_period(advisory.released_on, severity)
	within_grace_period == false

	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[severity, cve, advisory.advisory, advisory.released_on, grace_days],
		cve,
	)
}

# METADATA
# title: Release-time CVE data format
# description: >-
#   Require runtime collector data with RHSA CRITICAL and IMPORTANT arrays and
#   validate advisory IDs, release timestamps, CVE entries, and affected component
#   names. Require input.component_name to associate advisories with the evaluated
#   component. Empty severity arrays represent a successful collection with no advisories.
# custom:
#   short_name: runtime_data_format
#   failure_msg: 'Release-time CVE data has unexpected format: %s'
#   solution: >-
#     Provide runtime collector_data with RHSA CRITICAL and IMPORTANT arrays
#     containing advisory, released_on, cves, and components fields, and provide
#     input.component_name as a non-empty string.
#   pipeline_intention:
#   # Expected to run only in release pipeline
#   - release
#   - production
#   - staging
#   collections:
#   - redhat
#   - redhat_security
#   # Roll this out initially as a warning. Expect to change this date earlier
#   # once we are confident everything is working as expected
#   effective_on: 2027-07-01T00:00:00Z
#
deny contains result if {
	metadata.pipeline_intention_match(rego.metadata.chain())
	some message in _runtime_data_errors
	result := metadata.result_helper(rego.metadata.chain(), [message])
}

# METADATA
# title: Release-time CVE leeway rule data provided
# description: >-
#   Confirm that release_time_cve_leeway specifies non-negative integer day counts
#   for the supported advisory severity levels.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: Set release_time_cve_leeway to an object of severity-to-days mappings.
#   collections:
#   - redhat
#   - redhat_security
#   - policy_data
#   # Roll this out initially as a warning. Expect to change this date earlier
#   # once we are confident everything is working as expected
#   effective_on: 2027-07-01T00:00:00Z
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_valid_component_name(name) if {
	is_string(name)
	name != ""
}

# Validate the raw namespace: runtime_data() intentionally masks missing or
# non-object namespaces with {}, which must not count as successful collection.
# Report all data problems through one rule. Its effective_on date keeps these
# results non-blocking during rollout, rather than silently accepting bad data.
default _runtime_data := null

_runtime_data := data.rule_data__runtime__

_runtime_data_errors contains "input.component_name is required and must be a non-empty string" if {
	name := object.get(input, "component_name", null)
	not _valid_component_name(name)
}

_runtime_data_errors contains "rule_data__runtime__ is required and must be an object" if {
	is_null(_runtime_data)
}

_runtime_data_errors contains e.message if {
	not is_null(_runtime_data)
	advisories := {
		"type": "array",
		"items": {
			"type": "object",
			"required": ["advisory", "released_on", "cves", "components"],
			"properties": {
				"advisory": {"type": "string", "minLength": 1},
				# OPA's date-time format also accepts date-only strings. The parser
				# check in _runtime_data_errors below further requires RFC 3339.
				"released_on": {"type": "string", "format": "date-time"},
				"cves": {
					"type": "array",
					"minItems": 1,
					"items": {"type": "string", "minLength": 1},
				},
				"components": {
					"type": "array",
					"minItems": 1,
					"items": {"type": "string", "minLength": 1},
				},
			},
		},
	}
	some e in j.validate_schema(_runtime_data, {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"required": ["collector_data"],
		"properties": {"collector_data": {
			"type": "object",
			"required": ["RHSA"],
			"properties": {"RHSA": {
				"type": "object",
				"required": ["CRITICAL", "IMPORTANT"],
				"properties": {
					"CRITICAL": advisories,
					"IMPORTANT": advisories,
				},
				"additionalProperties": false,
			}},
		}},
	})
}

# Use the same parser as grace-period evaluation. JSON Schema's date-time
# checker also accepts date-only strings, which that parser cannot evaluate.
# Only report parser errors when the format check passes, to avoid duplicates.
_runtime_data_errors contains message if {
	some severity, advisories in _runtime_data.collector_data.RHSA
	is_array(advisories)
	some index, advisory in advisories
	is_string(advisory.released_on)
	[true, _] = json.match_schema(json.marshal(advisory.released_on), {"type": "string", "format": "date-time"})
	not time.parse_rfc3339_ns(advisory.released_on)
	message := sprintf("collector_data.RHSA.%s.%d.released_on: Must be an RFC 3339 timestamp", [severity, index])
}

_rule_data_key := "release_time_cve_leeway"

# With no override, rule_data.get supplies the usual severity defaults. For
# partial overrides, omitted supported severities have zero days of leeway.
# Only supported severities participate in enforcement; validate the original
# configuration separately so unknown keys are still reported.
_grace_period_days := object.union(zero_days, object.filter(configured, supported)) if {
	configured := rule_data.get(_rule_data_key)
	is_object(configured)
	supported := object.keys(rule_data.defaults[_rule_data_key])
	zero_days := {severity: 0 | some severity in supported}
} else := rule_data.get(_rule_data_key)

_rule_data_errors contains error if {
	days_schema := {"type": "integer", "minimum": 0}
	some e in j.validate_schema(rule_data.get(_rule_data_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"properties": {
			"CRITICAL": days_schema,
			"IMPORTANT": days_schema,
		},
		"additionalProperties": false,
	})
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_day_ns := ((24 * 60) * 60) * 1000000000

# Undefined for invalid timestamps or unsupported severities, rather than treating
# missing or malformed data as an advisory whose grace period has expired.
_within_grace_period(released_on, severity) := within if {
	released_ns := time.parse_rfc3339_ns(released_on)
	grace_days := _grace_period_days[severity]
	within := released_ns > (lib_time.effective_current_time_ns - (grace_days * _day_ns))
}
