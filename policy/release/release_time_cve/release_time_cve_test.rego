package release_time_cve_test

import rego.v1

import data.lib.assertions
import data.release_time_cve

_now := time.parse_rfc3339_ns("2026-10-30T14:37:22Z")

_advisory(id, released_on, cves) := {
	"advisory": id,
	"released_on": released_on,
	"cves": cves,
	"components": ["konflux-component-a"],
}

_collector(scan) := {"RHSA": object.union({"CRITICAL": [], "IMPORTANT": []}, scan.RHSA)}

_format_result(message) := {
	"code": "release_time_cve.runtime_data_format",
	"msg": sprintf("Release-time CVE data has unexpected format: %s", [message]),
}

_result(severity, cve, advisory, released_on, days) := {
	"code": "release_time_cve.advisory_grace_period_expired",
	"msg": sprintf(
		"%s CVE %s in advisory %s was released on %s (grace period: %d days)",
		[severity, cve, advisory, released_on, days],
	),
	"term": cve,
}

test_release_denies_cves_past_their_grace_periods if {
	scan := {"RHSA": {
		"CRITICAL": [
			_advisory("RHSA-2026:58936", "2026-08-03T14:37:22Z", ["CVE-2024-1234", "CVE-2024-1235"]),
			_advisory("RHSA-2026:52036", "2026-10-03T14:37:22Z", ["CVE-2024-8765"]),
		],
		"IMPORTANT": [
			_advisory("RHSA-2026:55440", "2026-08-30T14:37:22Z", ["CVE-2024-2345"]),
			_advisory("RHSA-2026:55441", "2026-10-01T14:37:22Z", ["CVE-2024-9999"]),
		],
	}}

	expected := {
		_result("CRITICAL", "CVE-2024-1234", "RHSA-2026:58936", "2026-08-03T14:37:22Z", 30),
		_result("CRITICAL", "CVE-2024-1235", "RHSA-2026:58936", "2026-08-03T14:37:22Z", 30),
		_result("IMPORTANT", "CVE-2024-2345", "RHSA-2026:55440", "2026-08-30T14:37:22Z", 60),
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-a"
}

test_snapshot_advisories_are_scoped_to_each_component if {
	released_on := "2026-08-03T14:37:22Z"
	scan := {"RHSA": {
		"CRITICAL": [
			_advisory("a-only", released_on, ["CVE-2024-1001"]),
			object.union(_advisory("b-only", released_on, ["CVE-2024-1002"]), {"components": ["konflux-component-b"]}),
		],
		"IMPORTANT": [object.union(
			_advisory("shared", released_on, ["CVE-2024-1003"]),
			{"components": ["konflux-component-a", "konflux-component-b"]},
		)],
	}}
	shared := _result("IMPORTANT", "CVE-2024-1003", "shared", released_on, 60)
	cases := [
		{"name": "konflux-component-a", "expected": {shared, _result("CRITICAL", "CVE-2024-1001", "a-only", released_on, 30)}},
		{"name": "konflux-component-b", "expected": {shared, _result("CRITICAL", "CVE-2024-1002", "b-only", released_on, 30)}},
		{"name": "konflux-component-c", "expected": set()},
	]
	every tc in cases {
		assertions.assert_equal_results(release_time_cve.deny, tc.expected) with input.component_name as tc.name
			with data.rule_data__runtime__.collector_data as scan
			with data.rule_data.pipeline_intention as "release"
			with data.config.policy.when_ns as _now
	}
}

test_invalid_component_name_reports_format_error if {
	scan := _collector({"RHSA": {"CRITICAL": [_advisory("expired", "2026-08-03T14:37:22Z", ["CVE-2024-1234"])]}})
	expected := {_format_result("input.component_name is required and must be a non-empty string")}
	assertions.assert_equal_results(release_time_cve.deny, expected) with input as {}
		with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
	every name in ["", null, 42, false, [], {}] {
		assertions.assert_equal_results(release_time_cve.deny, expected) with input.component_name as name
			with data.rule_data__runtime__.collector_data as scan
			with data.rule_data.pipeline_intention as "release"
			with data.config.policy.when_ns as _now
	}
}

test_collector_validation_includes_other_components if {
	advisory := object.union(
		_advisory("invalid", "not-a-date", ["CVE-2024-1234"]),
		{"components": ["konflux-component-b"]},
	)
	scan := _collector({"RHSA": {"CRITICAL": [advisory]}})
	expected := {_format_result("collector_data.RHSA.CRITICAL.0.released_on: Does not match format 'date-time'")}
	assertions.assert_equal_results(release_time_cve.deny, expected) with input.component_name as "konflux-component-a"
		with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
}

test_within_grace_period if {
	assertions.assert_equal(
		release_time_cve._within_grace_period("2026-10-03T14:37:22Z", "CRITICAL"),
		true,
	) with data.config.policy.when_ns as _now
	assertions.assert_equal(
		release_time_cve._within_grace_period("2026-09-30T14:37:22Z", "CRITICAL"),
		false,
	) with data.config.policy.when_ns as _now
	assertions.assert_equal(
		release_time_cve._within_grace_period("2026-10-01T14:37:22Z", "IMPORTANT"),
		true,
	) with data.config.policy.when_ns as _now
	assertions.assert_equal(
		release_time_cve._within_grace_period("2026-08-30T14:37:22Z", "IMPORTANT"),
		false,
	) with data.config.policy.when_ns as _now
}

test_grace_period_boundaries if {
	critical_at_30_days := time.format([time.add_date(_now, 0, 0, -30), "UTC", "2006-01-02T15:04:05Z07:00"])
	important_at_60_days := time.format([time.add_date(_now, 0, 0, -60), "UTC", "2006-01-02T15:04:05Z07:00"])
	scan := {"RHSA": {
		"CRITICAL": [
			_advisory("at-30", critical_at_30_days, ["CVE-2024-0001"]),
			_advisory("under-30", "2026-09-30T14:37:23Z", ["CVE-2024-0002"]),
		],
		"IMPORTANT": [
			_advisory("at-60", important_at_60_days, ["CVE-2024-0003"]),
			_advisory("under-60", "2026-08-31T14:37:23Z", ["CVE-2024-0004"]),
		],
	}}

	expected := {
		_result("CRITICAL", "CVE-2024-0001", "at-30", critical_at_30_days, 30),
		_result("IMPORTANT", "CVE-2024-0003", "at-60", important_at_60_days, 60),
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-a"
}

test_configured_leeway_overrides_defaults if {
	scan := {"RHSA": {
		"CRITICAL": [_advisory("at-1", "2026-10-29T14:37:22Z", ["CVE-2024-0009"])],
		"IMPORTANT": [_advisory("at-3", "2026-10-27T14:37:22Z", ["CVE-2024-0010"])],
	}}
	leeway := {"CRITICAL": 1, "IMPORTANT": 3}
	expected := {
		_result("CRITICAL", "CVE-2024-0009", "at-1", "2026-10-29T14:37:22Z", 1),
		_result("IMPORTANT", "CVE-2024-0010", "at-3", "2026-10-27T14:37:22Z", 3),
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data__configuration__.release_time_cve_leeway as leeway
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-a"
}

test_partial_leeway_override_uses_zero_for_omitted_severities if {
	scan := {"RHSA": {
		"CRITICAL": [_advisory("at-1", "2026-10-29T14:37:22Z", ["CVE-2024-0012"])],
		"IMPORTANT": [_advisory("recent-important", "2026-10-30T14:37:21Z", ["CVE-2024-0013"])],
	}}
	expected := {
		_result("CRITICAL", "CVE-2024-0012", "at-1", "2026-10-29T14:37:22Z", 1),
		_result("IMPORTANT", "CVE-2024-0013", "recent-important", "2026-10-30T14:37:21Z", 0),
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data__configuration__.release_time_cve_leeway as {"CRITICAL": 1}
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-a"
}

test_grace_period_days_excludes_unknown_severities if {
	assertions.assert_equal(release_time_cve._grace_period_days, {
		"CRITICAL": 1,
		"IMPORTANT": 0,
	}) with data.rule_data__configuration__.release_time_cve_leeway as {"CRITICAL": 1, "UNKNOWN": 10}
}

test_grace_period_days_preserves_non_object_values if {
	every configured in [[], "invalid", 42, null] {
		assertions.assert_equal(release_time_cve._grace_period_days, configured) with data.rule_data__configuration__.release_time_cve_leeway as configured
	}
}

test_unknown_leeway_severity_warns_without_enforcing_it if {
	scan := {"RHSA": {
		"CRITICAL": [_advisory("critical", "2026-08-03T14:37:22Z", ["CVE-2024-0014"])],
		"UNKNOWN": [_advisory("unknown", "2026-08-03T14:37:22Z", ["CVE-2024-0015"])],
		"IMPORTANT": [],
	}}
	expected := {
		_result("CRITICAL", "CVE-2024-0014", "critical", "2026-08-03T14:37:22Z", 1),
		_format_result("collector_data.RHSA: Additional property UNKNOWN is not allowed"),
		{
			"code": "release_time_cve.rule_data_provided",
			"msg": "Rule data release_time_cve_leeway has unexpected format: (Root): Additional property UNKNOWN is not allowed",
			"severity": "warning",
		},
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data__configuration__.release_time_cve_leeway as {"CRITICAL": 1, "UNKNOWN": 10}
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-a"
}

test_leeway_rule_data_valid if {
	assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as _collector({"RHSA": {}})
	assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as _collector({"RHSA": {}})
		with data.rule_data__configuration__.release_time_cve_leeway as {"CRITICAL": 7, "IMPORTANT": 21}
}

test_leeway_rule_data_invalid if {
	leeway := {
		"CRITICAL": -1,
		"IMPORTANT": "sixty",
		"UNKNOWN": 10,
	}
	expected := {
		{
			"code": "release_time_cve.rule_data_provided",
			"msg": "Rule data release_time_cve_leeway has unexpected format: IMPORTANT: Invalid type. Expected: integer, given: string",
			"severity": "failure",
		},
		{
			"code": "release_time_cve.rule_data_provided",
			"msg": "Rule data release_time_cve_leeway has unexpected format: CRITICAL: Must be greater than or equal to 0",
			"severity": "failure",
		},
		{
			"code": "release_time_cve.rule_data_provided",
			"msg": "Rule data release_time_cve_leeway has unexpected format: (Root): Additional property UNKNOWN is not allowed",
			"severity": "warning",
		},
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__ as {}
		with data.rule_data__configuration__.release_time_cve_leeway as leeway
}

test_leeway_rule_data_not_an_object if {
	expected := {{
		"code": "release_time_cve.rule_data_provided",
		"msg": "Rule data release_time_cve_leeway has unexpected format: (Root): Invalid type. Expected: object, given: array",
		"severity": "failure",
	}}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__ as {}
		with data.rule_data__configuration__.release_time_cve_leeway as []
}

test_no_denials_on_other_pipelines if {
	scan := {"RHSA": {"CRITICAL": [_advisory("old", "2026-08-03T14:37:22Z", ["CVE-2024-1234"])]}}

	assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "build"
		with data.config.policy.when_ns as _now
	assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as null
		with data.config.policy.when_ns as _now
}

test_invalid_advisory_fields_report_all_format_problems if {
	scan := _collector({"RHSA": {"CRITICAL": [
		_advisory("no-cves", "2026-08-03T14:37:22Z", []),
		_advisory("invalid-cves", "2026-08-03T14:37:22Z", ["", 42, null]),
		_advisory("invalid-date", "not-a-date", ["CVE-2024-1234"]),
	]}})
	expected := {
		_format_result("collector_data.RHSA.CRITICAL.0.cves: Array must have at least 1 items"),
		_format_result("collector_data.RHSA.CRITICAL.1.cves.0: String length must be greater than or equal to 1"),
		_format_result("collector_data.RHSA.CRITICAL.1.cves.1: Invalid type. Expected: string, given: integer"),
		_format_result("collector_data.RHSA.CRITICAL.1.cves.2: Invalid type. Expected: string, given: null"),
		_format_result("collector_data.RHSA.CRITICAL.2.released_on: Does not match format 'date-time'"),
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-a"
}

test_missing_advisory_fields_report_format_problems if {
	advisory := _advisory("recent", "2026-10-03T14:37:22Z", ["CVE-2024-1234"])
	every field in ["advisory", "released_on", "cves", "components"] {
		scan := _collector({"RHSA": {"CRITICAL": [object.remove(advisory, [field])]}})
		expected := {_format_result(sprintf("collector_data.RHSA.CRITICAL.0: %s is required", [field]))}
		assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
			with data.rule_data.pipeline_intention as "release"
			with data.config.policy.when_ns as _now
			with input.component_name as "konflux-component-a"
	}
}

test_invalid_runtime_structure if {
	cases := [
		{"runtime": null, "message": "rule_data__runtime__ is required and must be an object"},
		{"runtime": [], "message": "(Root): Invalid type. Expected: object, given: array"},
		{"runtime": {}, "message": "(Root): collector_data is required"},
		{"runtime": {"collector_data": null}, "message": "collector_data: Invalid type. Expected: object, given: null"},
		{"runtime": {"collector_data": {}}, "message": "collector_data: RHSA is required"},
		{"runtime": {"collector_data": {"RHSA": []}}, "message": "collector_data.RHSA: Invalid type. Expected: object, given: array"},
	]
	every tc in cases {
		assertions.assert_equal_results(release_time_cve.deny, {_format_result(tc.message)}) with data.rule_data__runtime__ as tc.runtime
			with data.rule_data.pipeline_intention as "release"
			with input.component_name as "konflux-component-a"
	}
}

test_missing_severity_arrays if {
	expected := {
		_format_result("collector_data.RHSA: CRITICAL is required"),
		_format_result("collector_data.RHSA: IMPORTANT is required"),
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as {"RHSA": {}}
		with data.rule_data.pipeline_intention as "release"
		with input.component_name as "konflux-component-a"
}

test_empty_collection_is_valid if {
	assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as {"RHSA": {"CRITICAL": [], "IMPORTANT": []}}
		with data.rule_data.pipeline_intention as "release"
		with input.component_name as "konflux-component-a"
}

test_released_on_requires_parseable_rfc3339_timestamp if {
	cases := [
		{"released_on": "2026-08-03", "message": "Must be an RFC 3339 timestamp"},
		{"released_on": "2026-08-03T14:37:22", "message": "Does not match format 'date-time'"},
		{"released_on": "2026-02-30T14:37:22Z", "message": "Does not match format 'date-time'"},
	]
	every tc in cases {
		scan := _collector({"RHSA": {"CRITICAL": [_advisory("invalid-date", tc.released_on, ["CVE-2024-1234"])]}})
		expected := {_format_result(sprintf("collector_data.RHSA.CRITICAL.0.released_on: %s", [tc.message]))}
		assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
			with input.component_name as "konflux-component-a"
			with data.rule_data.pipeline_intention as "release"
			with data.config.policy.when_ns as _now
	}
}

test_released_on_accepts_offsets_and_fractional_seconds if {
	every released_on in ["2026-10-03T14:37:22+02:00", "2026-10-03T14:37:22.123456789Z"] {
		scan := _collector({"RHSA": {"CRITICAL": [_advisory("recent", released_on, ["CVE-2024-1234"])]}})
		assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as scan
			with input.component_name as "konflux-component-a"
			with data.rule_data.pipeline_intention as "release"
			with data.config.policy.when_ns as _now
	}
}

test_invalid_advisory_types if {
	cases := [
		{"advisories": {}, "message": "collector_data.RHSA.CRITICAL: Invalid type. Expected: array, given: object"},
		{"advisories": [null], "message": "collector_data.RHSA.CRITICAL.0: Invalid type. Expected: object, given: null"},
		{"advisories": [object.union(_advisory("valid", "2026-11-03T14:37:22Z", ["CVE-2024-1234"]), {"advisory": ""})], "message": "collector_data.RHSA.CRITICAL.0.advisory: String length must be greater than or equal to 1"},
		{"advisories": [object.union(_advisory("valid", "2026-11-03T14:37:22Z", ["CVE-2024-1234"]), {"advisory": 42})], "message": "collector_data.RHSA.CRITICAL.0.advisory: Invalid type. Expected: string, given: integer"},
		{"advisories": [_advisory("invalid-cves", "2026-08-03T14:37:22Z", {})], "message": "collector_data.RHSA.CRITICAL.0.cves: Invalid type. Expected: array, given: object"},
		{"advisories": [_advisory("invalid-date", null, ["CVE-2024-1234"])], "message": "collector_data.RHSA.CRITICAL.0.released_on: Invalid type. Expected: string, given: null"},
	]
	every tc in cases {
		scan := _collector({"RHSA": {"CRITICAL": tc.advisories}})
		assertions.assert_equal_results(release_time_cve.deny, {_format_result(tc.message)}) with data.rule_data__runtime__.collector_data as scan
			with data.rule_data.pipeline_intention as "release"
			with data.config.policy.when_ns as _now
			with input.component_name as "konflux-component-a"
	}
}

test_advisory_components_validation if {
	advisory := _advisory("RHSA-2026:52036", "2026-10-03T14:37:22Z", ["CVE-2024-8765"])
	cases := [
		{"components": null, "message": "Invalid type. Expected: array, given: null"},
		{"components": "konflux-component-b", "message": "Invalid type. Expected: array, given: string"},
		{"components": [], "message": "Array must have at least 1 items"},
	]
	every tc in cases {
		scan := _collector({"RHSA": {"CRITICAL": [object.union(advisory, {"components": tc.components})]}})
		expected := {_format_result(sprintf("collector_data.RHSA.CRITICAL.0.components: %s", [tc.message]))}
		assertions.assert_equal_results(release_time_cve.deny, expected) with input.component_name as "konflux-component-a"
			with data.rule_data__runtime__.collector_data as scan
			with data.rule_data.pipeline_intention as "release"
			with data.config.policy.when_ns as _now
	}
	scan := _collector({"RHSA": {"CRITICAL": [object.union(advisory, {"components": ["", 42, null]})]}})
	expected := {
		_format_result("collector_data.RHSA.CRITICAL.0.components.0: String length must be greater than or equal to 1"),
		_format_result("collector_data.RHSA.CRITICAL.0.components.1: Invalid type. Expected: string, given: integer"),
		_format_result("collector_data.RHSA.CRITICAL.0.components.2: Invalid type. Expected: string, given: null"),
	}
	assertions.assert_equal_results(release_time_cve.deny, expected) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-a"
}

test_advisory_with_multiple_components_is_valid if {
	advisory := object.union(
		_advisory("RHSA-2026:52036", "2026-10-03T14:37:22Z", ["CVE-2024-8765"]),
		{"components": ["konflux-component-b", "konflux-component-c"]},
	)
	scan := _collector({"RHSA": {"CRITICAL": [advisory]}})
	assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as scan
		with data.rule_data.pipeline_intention as "release"
		with data.config.policy.when_ns as _now
		with input.component_name as "konflux-component-b"
}

test_runtime_format_rollout_metadata if {
	results := release_time_cve.deny with data.rule_data__runtime__ as {}
		with data.rule_data.pipeline_intention as "release"
		with input.component_name as "konflux-component-a"
	assertions.assert_equal(count(results), 1)
	every result in results {
		assertions.assert_equal(result.effective_on, "2027-07-01T00:00:00Z")
		assertions.assert_equal(result.collections, ["redhat", "redhat_security"])
	}
}

test_invalid_runtime_data_skipped_on_non_release_pipeline if {
	assertions.assert_empty(release_time_cve.deny) with data.rule_data__runtime__.collector_data as {"RHSA": []}
		with data.rule_data.pipeline_intention as "build"
}

test_absent_runtime_namespace if {
	assertions.assert_equal_results(release_time_cve.deny, {_format_result("rule_data__runtime__ is required and must be an object")}) with data.rule_data.pipeline_intention as "release"
		with input.component_name as "konflux-component-a"
}
