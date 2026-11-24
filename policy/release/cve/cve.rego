#
# METADATA
# title: CVE checks
# description: >-
#   This package is responsible for verifying a CVE scan was performed during
#   the build pipeline, and that the image under test does not contain CVEs
#   of certain security levels.
#
#
#   The behaviour of the rules in this package is influenced by rule data.
#   Firstly the rules can be configured to emit violations or warnings based on
#   the availability of the vulnerability fix: patched -- if there is a
#   remediation available, e.g. new version with a fix, or unpatched -- if there
#   is, currently, no remidiation available. Secondly per severity: critical,
#   high, medium, low or unknown choice can be made of the rule outcome: failure
#   or warning. And lastly, per severity, choice can be made of how many leeway
#   days are allowed before a vulnerability causing a failure will be reported
#   as a warning instead.
#
#
#   In the following example if rule data configuration, failures will be
#   reported for critical and high patched vulnerabilities, for critical
#   unpatched vulnerabilities only, warnings will be reported for medium and low
#   patched, and for high and medium unpatched vulnerabilities. For critical and
#   high patched vulnerabilities a leeway of 10 days is allowed.
#
#
#   .Example rule data
#
#   [source,yaml]
#
#   ----
#
#   restrict_cve_security_levels:
#     - critical
#     - high
#   warn_cve_security_levels:
#     - medium
#     - low
#   restrict_unpatched_cve_security_levels:
#     - critical
#   warn_unpatched_cve_security_levels:
#     - high
#     - medium
#   cve_leeway:
#     critical: 10
#     high: 10
#   ----
#
package cve

import rego.v1

import data.lib
import data.lib.image
import data.lib.json as j
import data.lib.metadata
import data.lib.oci
import data.lib.rule_data

# METADATA
# title: Non-blocking CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that have a known fix
#   and meet a certain security level have not been detected. If detected, this policy rule will
#   raise a warning. By default, the list of CVE security levels used by this policy is empty.
#   However, this is configurable by the rule data key `warn_cve_security_levels`. The available
#   levels are critical, high, medium, low, and unknown.
# custom:
#   short_name: cve_warnings
#   failure_msg: Found %q non-blocking vulnerability of %s security level
#   solution: >-
#     Make sure to address any CVE's related to the image.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - cve.cve_results_found
#
warn contains result if {
	some level, vulns in _grouped_vulns.warn_cve_security_levels
	some vuln in vulns

	name := _name(vuln)
	result := metadata.result_helper_with_term(rego.metadata.chain(), [name, level], name)
}

# METADATA
# title: Non-blocking unpatched CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that do NOT have a
#   known fix and meet a certain security level have not been detected. If detected, this policy
#   rule will raise a warning. By default, only CVEs of critical and high security level cause a
#   warning. This is configurable by the rule data key `warn_unpatched_cve_security_levels`. The
#   available levels are critical, high, medium, low, and unknown.
# custom:
#   short_name: unpatched_cve_warnings
#   failure_msg: Found %q non-blocking unpatched vulnerability of %s security level
#   solution: >-
#     CVEs without a known fix can only be remediated by either removing the impacted dependency, or
#     by waiting for a fix to be available.
#   collections:
#   - minimal
#   - redhat
#   depends_on:
#   - cve.cve_results_found
#
warn contains result if {
	some level, vulns in _grouped_vulns.warn_unpatched_cve_security_levels
	some vuln in vulns

	name := _name(vuln)
	result := metadata.result_helper_with_term(rego.metadata.chain(), [name, level], name)
}

# METADATA
# title: Blocking CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that have a known fix
#   and meet a certain security level have not been detected. If detected, this policy rule will
#   fail. By default, only CVEs of critical and high security level cause a failure. This is
#   configurable by the rule data key `restrict_cve_security_levels`. The available levels are
#   critical, high, medium, low, and unknown. In addition to that leeway can be granted per severity
#   using the `cve_leeway` rule data key containing days of allowed leeway, measured as time between
#   found vulnerability's public disclosure date and current effective time, per severity level.
# custom:
#   short_name: cve_blockers
#   failure_msg: Found %q vulnerability of %s security level
#   solution: >-
#     Make sure to address any CVE's related to the image.
#   collections:
#   - minimal
#   - redhat
#   - redhat_security
#   depends_on:
#   - cve.cve_results_found
#
deny contains result if {
	some level, vulns in _grouped_vulns.restrict_cve_security_levels
	some vuln in vulns

	leeway := _compute_leeway(vuln, level)
	name := _name(vuln)

	result := _with_effective_on(
		metadata.result_helper_with_term(rego.metadata.chain(), [name, level], name),
		leeway,
	)
}

# METADATA
# title: Blocking unpatched CVE check
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure CVEs that do NOT have a
#   known fix and meet a certain security level have not been detected. If detected, this policy
#   rule will fail. By default, the list of security levels used by this policy is empty. This is
#   configurable by the rule data key `restrict_unpatched_cve_security_levels`. The available levels
#   are critical, high, medium, low, and unknown. In addition to that leeway can be granted per
#   severity using the `cve_leeway` rule data key containing days of allowed leeway, measured as
#   time between found vulnerability's public disclosure date and current effective time, per
#   severity level.
# custom:
#   short_name: unpatched_cve_blockers
#   failure_msg: Found %q unpatched vulnerability of %s security level
#   solution: >-
#     CVEs without a known fix can only be remediated by either removing the impacted dependency, or
#     by waiting for a fix to be available.
#   collections:
#   - minimal
#   - redhat
#   - redhat_security
#   depends_on:
#   - cve.cve_results_found
#
deny contains result if {
	some level, vulns in _grouped_vulns.restrict_unpatched_cve_security_levels
	some vuln in vulns

	leeway := _compute_leeway(vuln, level)
	name := _name(vuln)

	result := _with_effective_on(
		metadata.result_helper_with_term(rego.metadata.chain(), [name, level], name),
		leeway,
	)
}

# METADATA
# title: CVE scan results found
# description: >-
#   Confirm that CVE scan task results (Clair, TPA, or roxctl) are present in the SLSA Provenance
#   attestation of the build pipeline.
# custom:
#   short_name: cve_results_found
#   failure_msg: CVE scan results were not found
#   solution: >-
#     Make sure there is a successful task in the build pipeline that runs a
#     CVE scan (Clair, TPA, or roxctl).
#   collections:
#   - minimal
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	# No report has data that resembles a clair-scan report
	not _has_clair_vulnerabilities

	# No report has data that resembles a tpa-scan report
	not _has_tpa_providers

	# No report has data that resembles a roxctl-scan report
	not _has_rox_vulnerabilities

	# Index Images don't get a CVE scan report since it's just a reference to Image Manifests. The
	# report is only expected to be found on each of the individual Image Manifests.
	not image.is_image_index(input.image.ref)
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `restrict_cve_security_levels`,	`warn_cve_security_levels`,
#   `restrict_unpatched_cve_security_levels`, and `warn_unpatched_cve_security_levels`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - minimal
#   - redhat
#   - policy_data
#   - redhat_security
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# METADATA
# title: Rule data provided (v2)
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `restrict_cve_security_levels`,	`warn_cve_security_levels`,
#   `restrict_unpatched_cve_security_levels`, and `warn_unpatched_cve_security_levels`.
#   Unlike rule_data_provided, a present value of the wrong type (for example a scalar or a string
#   containing JSON text) is rejected instead of silently skipping the check.
# custom:
#   short_name: rule_data_provided_v2
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - minimal
#   - redhat
#   - policy_data
#   - redhat_security
#   effective_on: 2027-01-11T00:00:00Z
#
deny contains result if {
	some e in _rule_data_errors_v2
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# A sanity check for the data format. Clair reports
# are expected to have a vulnerabilities key.
_has_clair_vulnerabilities if {
	some report in _cve_scan_reports
	report.vulnerabilities
}

# A sanity check for the data format. TPA-scan reports
# are expected to have a providers key.
_has_tpa_providers if {
	some report in _cve_scan_reports
	report.providers
}

# A sanity check for the data format. roxctl reports
# are expected to have a roxctl_new key containing an array.
_has_rox_vulnerabilities if {
	some report in _cve_scan_reports
	report.roxctl_new
}

# Create a data structure that represents the different vulnerabilities sorted in different
# buckets, making it easier to implement the different rules.
# _grouped_vulns := {
# 	"restrict_cve_security_levels": {
# 		"critical": {vuln1, vuln2}
# 	},
# 	"restrict_unpatched_cve_security_levels": {
# 		"critical": {vuln3},
# 		"high": {vuln4},
# 	}
# }
_grouped_vulns[key][level] contains vuln if {
	some key, patched in _levels_keys_patched
	levels := rule_data.get(key)
	some report in _cve_scan_reports
	some vuln in report.vulnerabilities
	level := lower(object.get(vuln, "normalized_severity", "unknown"))

	# Match on the expected level.
	level in levels

	# Match on expected patch state.
	patched == _is_vuln_patched(vuln)
}

# Process TPA issues into the same grouped structure
_grouped_vulns[key][level] contains issue if {
	some key, patched in _levels_keys_patched
	levels := rule_data.get(key)
	some issue in _all_tpa_issues
	level := lower(object.get(issue, "severity", "unknown"))

	# Match on the expected level.
	level in levels

	# TPA issues don't have fixed_in_version, so we treat them as patched for now
	patched == true
}

# Process roxctl vulnerabilities into the same grouped structure
_grouped_vulns[key][level] contains vuln if {
	some key, patched in _levels_keys_patched
	levels := rule_data.get(key)
	some report in _cve_scan_reports
	is_array(report.roxctl_new)
	some vuln in report.roxctl_new
	is_object(vuln)
	level := _rox_normalized_severity(vuln)

	# Match on the expected level.
	level in levels

	# Match on expected patch state.
	patched == _is_rox_vuln_patched(vuln)
}

# Return whether or not the vulnerability is patched. Because this function is used in a comparison
# it must always return a value, thus the `else` clause.
_is_vuln_patched(vuln) if {
	fixed_in_version := object.get(vuln, "fixed_in_version", "")
	fixed_in_version != ""
} else := false

_is_rox_vuln_patched(vuln) if {
	fixed_by := object.get(vuln, "fixedBy", "")
	fixed_by != ""
} else := false

_rox_normalized_severity(vuln) := level if {
	raw := object.get(vuln, "severity", "")
	level := object.get(_rox_severity_map, raw, "unknown")
}

_rox_severity_map := {
	"CRITICAL_VULNERABILITY_SEVERITY": "critical",
	"IMPORTANT_VULNERABILITY_SEVERITY": "high",
	"MODERATE_VULNERABILITY_SEVERITY": "medium",
	"LOW_VULNERABILITY_SEVERITY": "low",
}

# Map each rule data key to whether or not they apply to patched dependencies.
_levels_keys_patched := {
	"warn_cve_security_levels": true,
	"warn_unpatched_cve_security_levels": false,
	"restrict_cve_security_levels": true,
	"restrict_unpatched_cve_security_levels": false,
}

# Extracts all CVE scan reports attached to the image.
# Reports can be generated by clair-scan, tpa-scan, or roxctl-scan tasks.
_cve_scan_reports contains report if {
	input_image := image.parse(input.image.ref)

	some reports in lib.results_named(_reports_result_name)
	report_image := object.union(input_image, {"digest": reports.value[input_image.digest]})
	report_ref := image.str(report_image)
	report_manifest := ec.oci.image_manifest(report_ref)

	some layer in report_manifest.layers
	layer.mediaType in _report_oci_mime_types
	report_blob := object.union(input_image, {"digest": layer.digest})
	report_blob_ref := image.str(report_blob)

	report := oci.parsed_blob_if_valid(report_blob_ref)
}

# Clair format uses "name", roxctl format uses "cve", TPA format uses "id"
_name(vuln) := object.get(vuln, "name", object.get(vuln, "cve", object.get(vuln, "id", "UNKNOWN")))

_reports_result_name := "REPORTS"

_report_oci_mime_types := {
	"application/vnd.redhat.clair-report+json",
	"application/vnd.redhat.tpa-report+json",
	"application/vnd.redhat.rox-report+json",
}

# Add effective_on to result only if it's not null.
_with_effective_on(result, effective_on) := object.union(
	result,
	{"effective_on": effective_on},
) if {
	effective_on != null
}

# tpa-scan issues don't have an "issued" date, so effective_on will
# always be null for them.
_with_effective_on(result, null) := result

_compute_leeway(vuln, severity) := effective_on if {
	issued := object.get(vuln, "issued", null)
	ns := time.parse_rfc3339_ns(issued)

	leeway := rule_data.get("cve_leeway")
	years := 0
	months := 0
	days := leeway[severity]

	new_ns := time.add_date(ns, years, months, days)
	effective_on := time.format([new_ns, "UTC", "2006-01-02T15:04:05Z07:00"])
} else := object.get(vuln, "issued", null)

_rule_data_errors contains error if {
	some key in _security_level_keys

	some e in j.validate_schema(rule_data.get(key), _security_levels_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	some e in j.validate_schema(rule_data.get("cve_leeway"), _leeway_schema)
	error := {
		"message": sprintf("Rule data cve_leeway has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

# _rule_data_errors_v2 mirrors _rule_data_errors but validates the values as
# native rule data: a present scalar value is reported as a format violation
# instead of raising a builtin error that suppresses the result, and a string
# is never interpreted as serialized JSON.
_rule_data_errors_v2 contains error if {
	some key in _security_level_keys

	some e in j.validate_schema_native(rule_data.get(key), _security_levels_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors_v2 contains error if {
	some e in j.validate_schema_native(rule_data.get("cve_leeway"), _leeway_schema)
	error := {
		"message": sprintf("Rule data cve_leeway has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

_security_level_keys := [
	"restrict_cve_security_levels",
	"warn_cve_security_levels",
	"restrict_unpatched_cve_security_levels",
	"warn_unpatched_cve_security_levels",
]

_security_levels_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "array",
	"items": {"enum": ["critical", "high", "medium", "low", "unknown"]},
	"uniqueItems": true,
}

_leeway_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "object",
	"properties": {
		"critical": {"type": "integer", "minimum": 0},
		"high": {"type": "integer", "minimum": 0},
		"medium": {"type": "integer", "minimum": 0},
		"low": {"type": "integer", "minimum": 0},
		"unknown": {"type": "integer", "minimum": 0},
	},
	"additionalProperties": false,
}

# Collect all issues from all providers, sources, and dependencies (including transitive)
_all_tpa_issues contains issue if {
	some report in _cve_scan_reports
	some provider_name, provider in report.providers
	some source_name, source in provider.sources

	# Direct dependency issues
	some dep in source.dependencies
	some issue in dep.issues
}

_all_tpa_issues contains issue if {
	some report in _cve_scan_reports
	some provider_name, provider in report.providers
	some source_name, source in provider.sources

	# Transitive dependency issues
	some dep in source.dependencies
	some trans_dep in dep.transitive
	some issue in trans_dep.issues
}
