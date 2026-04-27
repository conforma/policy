package cve_test

import rego.v1

import data.cve

import data.lib.assertions
import data.lib.tekton_test
import data.lib.time as lib_time
import data.lib_test

test_success if {
	assertions.assert_empty(cve.deny | cve.warn) with input.attestations as _no_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
}

test_success_with_rule_data if {
	assertions.assert_empty(cve.deny | cve.warn) with input.attestations as _with_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data.restrict_cve_security_levels as []
		with data.rule_data.warn_unpatched_cve_security_levels as []
}

test_failure if {
	expected_deny := {
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Critical-0001\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0001",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Critical-0002\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0002",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-High-0003\" vulnerability of high security level",
			"term": "CVE-9999-High-0003",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-High-0004\" vulnerability of high security level",
			"term": "CVE-9999-High-0004",
		},
	}

	assertions.assert_equal_results(cve.deny, expected_deny) with input.attestations as _with_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
}

test_failure_with_rule_data if {
	expected := {
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Low-0007\" vulnerability of low security level",
			"term": "CVE-9999-Low-0007",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Low-0008\" vulnerability of low security level",
			"term": "CVE-9999-Low-0008",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Unknown-0009\" vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0009",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Unknown-0010\" vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0010",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"msg": "Found \"CVE-9999-Low-0017\" unpatched vulnerability of low security level",
			"term": "CVE-9999-Low-0017",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"msg": "Found \"CVE-9999-Low-0018\" unpatched vulnerability of low security level",
			"term": "CVE-9999-Low-0018",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"msg": "Found \"CVE-9999-Unknown-0019\" unpatched vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0019",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"msg": "Found \"CVE-9999-Unknown-0020\" unpatched vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0020",
		},
	}

	assertions.assert_equal_results(cve.deny, expected) with input.attestations as _with_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data.restrict_cve_security_levels as ["unknown", "low"]
		with data.rule_data.restrict_unpatched_cve_security_levels as ["unknown", "low"]
}

test_failure_with_leeway if {
	# Issued date (2022-03-26T00:00:00Z) plus leeway (3 days)
	leeway_effective_on := "2022-03-29T00:00:00Z"
	expected_deny := {
		{
			"code": "cve.cve_blockers",
			"effective_on": leeway_effective_on,
			"msg": "Found \"CVE-9999-Critical-0001\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0001",
		},
		{
			"code": "cve.cve_blockers",
			"effective_on": leeway_effective_on,
			"msg": "Found \"CVE-9999-Critical-0002\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0002",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"effective_on": leeway_effective_on,
			"msg": "Found \"CVE-9999-Critical-0011\" unpatched vulnerability of critical security level",
			"term": "CVE-9999-Critical-0011",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"effective_on": leeway_effective_on,
			"msg": "Found \"CVE-9999-Critical-0012\" unpatched vulnerability of critical security level",
			"term": "CVE-9999-Critical-0012",
		},
	}

	# Violations are updated with an effective_on in the future.
	assertions.assert_equal_results_no_collections(cve.deny, expected_deny) with input.attestations as _with_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data.cve_leeway as {"critical": 3}
		with data.rule_data.restrict_cve_security_levels as ["critical"]
		with data.rule_data.restrict_unpatched_cve_security_levels as ["critical"]
		with data.rule_data.warn_cve_security_levels as []
		with data.rule_data.warn_unpatched_cve_security_levels as []
		with lib_time.effective_current_time_ns as time.parse_rfc3339_ns("2022-03-26T00:00:00Z")
}

test_failure_with_missing_leeway_data if {
	# When a leeway is not defined, or is missing for a particular level, effective_on is the
	# issued date.
	expected_effective_on := "2022-03-26T00:00:00Z"
	expected_deny := {
		{
			"code": "cve.cve_blockers",
			"effective_on": expected_effective_on,
			"msg": "Found \"CVE-9999-Critical-0001\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0001",
		},
		{
			"code": "cve.cve_blockers",
			"effective_on": expected_effective_on,
			"msg": "Found \"CVE-9999-Critical-0002\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0002",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"effective_on": expected_effective_on,
			"msg": "Found \"CVE-9999-Critical-0011\" unpatched vulnerability of critical security level",
			"term": "CVE-9999-Critical-0011",
		},
		{
			"code": "cve.unpatched_cve_blockers",
			"effective_on": expected_effective_on,
			"msg": "Found \"CVE-9999-Critical-0012\" unpatched vulnerability of critical security level",
			"term": "CVE-9999-Critical-0012",
		},
	}

	# Violations are updated with an effective_on in the future.
	assertions.assert_equal_results_no_collections(cve.deny, expected_deny) with input.attestations as _with_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data.cve_leeway as {}
		with data.rule_data.restrict_cve_security_levels as ["critical"]
		with data.rule_data.restrict_unpatched_cve_security_levels as ["critical"]
		with data.rule_data.warn_cve_security_levels as []
		with data.rule_data.warn_unpatched_cve_security_levels as []
		with lib_time.effective_current_time_ns as time.parse_rfc3339_ns("2022-03-26T00:00:00Z")
}

test_warn if {
	expected := {
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Critical-0011\" non-blocking unpatched vulnerability of critical security level",
			"term": "CVE-9999-Critical-0011",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Critical-0012\" non-blocking unpatched vulnerability of critical security level",
			"term": "CVE-9999-Critical-0012",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-High-0013\" non-blocking unpatched vulnerability of high security level",
			"term": "CVE-9999-High-0013",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-High-0014\" non-blocking unpatched vulnerability of high security level",
			"term": "CVE-9999-High-0014",
		},
	}

	assertions.assert_equal_results(cve.warn, expected) with input.attestations as _with_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
}

test_warn_with_rule_data if {
	expected := {
		{
			"code": "cve.cve_warnings",
			"msg": "Found \"CVE-9999-Low-0007\" non-blocking vulnerability of low security level",
			"term": "CVE-9999-Low-0007",
		},
		{
			"code": "cve.cve_warnings",
			"msg": "Found \"CVE-9999-Low-0008\" non-blocking vulnerability of low security level",
			"term": "CVE-9999-Low-0008",
		},
		{
			"code": "cve.cve_warnings",
			"msg": "Found \"CVE-9999-Medium-0005\" non-blocking vulnerability of medium security level",
			"term": "CVE-9999-Medium-0005",
		},
		{
			"code": "cve.cve_warnings",
			"msg": "Found \"CVE-9999-Medium-0006\" non-blocking vulnerability of medium security level",
			"term": "CVE-9999-Medium-0006",
		},
		{
			"code": "cve.cve_warnings",
			"msg": "Found \"CVE-9999-Unknown-0009\" non-blocking vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0009",
		},
		{
			"code": "cve.cve_warnings",
			"msg": "Found \"CVE-9999-Unknown-0010\" non-blocking vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0010",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Low-0017\" non-blocking unpatched vulnerability of low security level",
			"term": "CVE-9999-Low-0017",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Low-0018\" non-blocking unpatched vulnerability of low security level",
			"term": "CVE-9999-Low-0018",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Medium-0015\" non-blocking unpatched vulnerability of medium security level",
			"term": "CVE-9999-Medium-0015",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Medium-0016\" non-blocking unpatched vulnerability of medium security level",
			"term": "CVE-9999-Medium-0016",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Unknown-0019\" non-blocking unpatched vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0019",
		},
		{
			"code": "cve.unpatched_cve_warnings",
			"msg": "Found \"CVE-9999-Unknown-0020\" non-blocking unpatched vulnerability of unknown security level",
			"term": "CVE-9999-Unknown-0020",
		},
	}

	assertions.assert_equal_results(cve.warn, expected) with input.attestations as _with_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data.warn_cve_security_levels as ["medium", "low", "unknown"]
		with data.rule_data.warn_unpatched_cve_security_levels as ["medium", "low", "unknown"]
}

test_full_report_fetch_issue if {
	ref := "registry.io/repository/image@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"
	descriptor := {"mediaType": "application/vnd.docker.distribution.manifest.v1+json"}

	expected := {{
		"code": "cve.cve_results_found",
		"msg": "CVE scan results were not found",
	}}

	assertions.assert_equal_results(cve.deny, expected) with input.image.ref as ref
		with ec.oci.descriptor as descriptor

	assertions.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
		with input.image.ref as ref
		with ec.oci.descriptor as descriptor
		with ec.oci.image_manifest as null
	assertions.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
		with input.image.ref as ref
		with ec.oci.descriptor as descriptor
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as null

	assertions.assert_empty(cve.warn) with input.attestations as _no_vuln_attestations
		with input.image.ref as ref
		with ec.oci.descriptor as descriptor
		with ec.oci.image_manifest as null
	assertions.assert_empty(cve.warn) with input.attestations as _no_vuln_attestations
		with input.image.ref as ref
		with ec.oci.descriptor as descriptor
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as null
}

test_rule_data_provided if {
	d := {
		"restrict_cve_security_levels": [
			# Wrong type
			1,
			# Duplicated items
			"high",
			"high",
		],
		# We don't need to check the different errors for each key as they are processed the same
		# way. But we do want to, at least, verify a single error.
		"warn_cve_security_levels": [1],
		"restrict_unpatched_cve_security_levels": [1],
		"warn_unpatched_cve_security_levels": [1],
	}

	expected := {
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data restrict_cve_security_levels has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data restrict_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
			"severity": "failure",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data restrict_unpatched_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
			"severity": "failure",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data warn_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
			"severity": "failure",
		},
		{
			"code": "cve.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data warn_unpatched_cve_security_levels has unexpected format: 0: 0 must be one of the following: \"critical\", \"high\", \"medium\", \"low\", \"unknown\"",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as d
}

test_leeway_rule_data_check if {
	d := {"cve_leeway": {
		# wrong key
		"blooper": 1,
		# wrong type
		"critical": "one",
		# negative number
		"high": -10,
		# all good
		"medium": 10,
	}}

	expected := {
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data cve_leeway has unexpected format: (Root): Additional property blooper is not allowed",
			"severity": "warning",
		},
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data cve_leeway has unexpected format: critical: Invalid type. Expected: integer, given: string",
			"severity": "failure",
		},
		{
			"code": "cve.rule_data_provided",
			"msg": "Rule data cve_leeway has unexpected format: high: Must be greater than or equal to 0",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as d
}

_vuln(id, severity, fixed_in, issued) := v if {
	# The clair report uses a unique "fingerprint" as the key/attribute for each vulnerability in
	# the report object. Here we simulate the intent which is good enough given that the policies
	# ignore the value of this key/attribute.
	fingerprint := base64.encode(sprintf("ignore-%s-%d", [severity, id]))

	# Each CVE entry has a name. The format varies based on the reporting authoritiy, e.g.
	# CVE-2024-52533 and GO-2024-3333. Here we make up our own convention to facilitate testing.
	name := sprintf("CVE-9999-%s-%0.4d", [severity, id])

	v := {fingerprint: {
		"name": name,
		"fixed_in_version": fixed_in,
		"normalized_severity": severity,
		"issued": issued,
	}}
}

vulnerabilities := object.union_n([
	_vuln(1, "Critical", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(2, "Critical", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(3, "High", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(4, "High", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(5, "Medium", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(6, "Medium", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(7, "Low", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(8, "Low", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(9, "Unknown", "1.0", "2022-03-26T00:00:00Z"),
	_vuln(10, "Unknown", "1.0", "2022-03-26T00:00:00Z"),
])

unpatched_vulnerabilities := object.union_n([
	_vuln(11, "Critical", "", "2022-03-26T00:00:00Z"),
	_vuln(12, "Critical", "", "2022-03-26T00:00:00Z"),
	_vuln(13, "High", "", "2022-03-26T00:00:00Z"),
	_vuln(14, "High", "", "2022-03-26T00:00:00Z"),
	_vuln(15, "Medium", "", "2022-03-26T00:00:00Z"),
	_vuln(16, "Medium", "", "2022-03-26T00:00:00Z"),
	_vuln(17, "Low", "", "2022-03-26T00:00:00Z"),
	_vuln(18, "Low", "", "2022-03-26T00:00:00Z"),
	_vuln(19, "Unknown", "", "2022-03-26T00:00:00Z"),
	_vuln(20, "Unknown", "", "2022-03-26T00:00:00Z"),
])

_cve_scan_report := {"vulnerabilities": object.union(vulnerabilities, unpatched_vulnerabilities)}

_manifests := {
	"registry.io/repository/image@sha256:report_digest": {"layers": [{
		"mediaType": "application/vnd.redhat.clair-report+json",
		"digest": "sha256:report_blob_digest",
	}]},
	"registry.io/repository/image@sha256:no_vulnerabilities_report_digest": {"layers": [{
		"mediaType": "application/vnd.redhat.clair-report+json",
		"digest": "sha256:no_vulnerabilities_report_blob_digest",
	}]},
}

_blobs := {
	"registry.io/repository/image@sha256:report_blob_digest": json.marshal(_cve_scan_report),
	"registry.io/repository/image@sha256:no_vulnerabilities_report_blob_digest": json.marshal({"vulnerabilities": {}}),
}

_mock_image_manifest(ref) := _manifests[ref]

_mock_blob(ref) := _blobs[ref]

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_no_vuln_attestations := _attestations_with_reports({"sha256:image_digest": "sha256:no_vulnerabilities_report_digest"})

_with_vuln_attestations := _attestations_with_reports({"sha256:image_digest": "sha256:report_digest"})

_attestations_with_reports(reports) := attestations if {
	slsav1_task_with_result := tekton_test.resolved_slsav1_task("clair-scan", [], [{
		"name": cve._reports_result_name,
		"type": "string",
		"value": reports,
	}])

	att1 := lib_test.att_mock_helper_ref(
		cve._reports_result_name,
		reports,
		"clair-scan",
		_bundle,
	)

	task_with_bundle := tekton_test.with_bundle(slsav1_task_with_result, _bundle)
	att2 := tekton_test.slsav1_attestation([task_with_bundle])
	attestations := [att1, att2]
}

test_success_with_tpa_report if {
	no_vuln_tpa_attestations := _attestations_with_tpa_reports({"sha256:image_digest": "sha256:no_vulnerabilities_tpa_report_digest"})
	assertions.assert_empty(cve.deny | cve.warn) with input.attestations as no_vuln_tpa_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_tpa_image_manifest
		with ec.oci.blob as _mock_tpa_blob
}

test_success_with_both_clair_and_tpa_reports if {
	assertions.assert_empty(cve.deny | cve.warn) with input.attestations as _no_vuln_both_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest_no_vuln_both
		with ec.oci.blob as _mock_blob_no_vuln_both
}

_no_vuln_both_attestations := attestations if {
	clair_task := tekton_test.resolved_slsav1_task("clair-scan", [], [{
		"name": cve._reports_result_name,
		"type": "string",
		"value": {"sha256:image_digest": "sha256:no_vulnerabilities_report_digest"},
	}])

	tpa_task := tekton_test.resolved_slsav1_task("tpa-scan", [], [{
		"name": cve._reports_result_name,
		"type": "string",
		"value": {"sha256:image_digest": "sha256:no_vulnerabilities_tpa_report_digest"},
	}])

	clair_with_bundle := tekton_test.with_bundle(clair_task, _bundle)
	tpa_with_bundle := tekton_test.with_bundle(tpa_task, _bundle)
	att := tekton_test.slsav1_attestation([clair_with_bundle, tpa_with_bundle])
	attestations := [att]
}

_manifests_no_vuln_both := object.union(_manifests, _tpa_manifests)

_blobs_no_vuln_both := object.union(_blobs, _tpa_blobs)

_mock_image_manifest_no_vuln_both(ref) := _manifests_no_vuln_both[ref]

_mock_blob_no_vuln_both(ref) := _blobs_no_vuln_both[ref]

# TPA scan tests

test_tpa_all_issues_collects_direct_and_transitive if {
	expected := {
		{
			"id": "CVE-2021-38561",
			"severity": "HIGH",
			"source": "osv-github",
			"title": "golang.org/x/text vulnerability",
		},
		{
			"id": "CVE-2022-32149",
			"severity": "HIGH",
			"source": "osv-github",
			"title": "golang.org/x/text DoS vulnerability",
		},
		{
			"id": "CVE-2025-6020",
			"severity": "HIGH",
			"source": "redhat-csaf",
			"title": "Linux-pam directory traversal",
		},
		{
			"id": "CVE-2026-27135",
			"severity": "HIGH",
			"source": "redhat-csaf",
			"title": "nghttp2 DoS",
		},
	}

	result := cve._all_tpa_issues with input.attestations as _tpa_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_tpa_image_manifest
		with ec.oci.blob as _mock_tpa_blob

	assertions.assert_equal(result, expected)
}

test_tpa_issues_trigger_deny if {
	expected := {
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2021-38561\" vulnerability of high security level",
			"term": "CVE-2021-38561",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2022-32149\" vulnerability of high security level",
			"term": "CVE-2022-32149",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2025-6020\" vulnerability of high security level",
			"term": "CVE-2025-6020",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2026-27135\" vulnerability of high security level",
			"term": "CVE-2026-27135",
		},
	}

	assertions.assert_equal_results(cve.deny, expected) with input.attestations as _tpa_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_tpa_image_manifest
		with ec.oci.blob as _mock_tpa_blob
}

test_both_clair_and_tpa_vulns_reported if {
	expected := {
		# Clair critical and high vulns
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Critical-0001\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0001",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-Critical-0002\" vulnerability of critical security level",
			"term": "CVE-9999-Critical-0002",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-High-0003\" vulnerability of high security level",
			"term": "CVE-9999-High-0003",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-9999-High-0004\" vulnerability of high security level",
			"term": "CVE-9999-High-0004",
		},
		# TPA high vulns
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2021-38561\" vulnerability of high security level",
			"term": "CVE-2021-38561",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2022-32149\" vulnerability of high security level",
			"term": "CVE-2022-32149",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2025-6020\" vulnerability of high security level",
			"term": "CVE-2025-6020",
		},
		{
			"code": "cve.cve_blockers",
			"msg": "Found \"CVE-2026-27135\" vulnerability of high security level",
			"term": "CVE-2026-27135",
		},
	}

	assertions.assert_equal_results(cve.deny, expected) with input.attestations as _both_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest_both_vulns
		with ec.oci.blob as _mock_blob_both_vulns
		with data.rule_data.restrict_cve_security_levels as ["critical", "high"]
}

# Both Clair and TPA reports in one pipeline run, with different CVEs in each
_both_attestations := attestations if {
	clair_task := tekton_test.resolved_slsav1_task("clair-scan", [], [{
		"name": cve._reports_result_name,
		"type": "string",
		"value": {"sha256:image_digest": "sha256:report_digest"},
	}])

	tpa_task := tekton_test.resolved_slsav1_task("tpa-scan", [], [{
		"name": cve._reports_result_name,
		"type": "string",
		"value": {"sha256:image_digest": "sha256:tpa_report_digest"},
	}])

	clair_with_bundle := tekton_test.with_bundle(clair_task, _bundle)
	tpa_with_bundle := tekton_test.with_bundle(tpa_task, _bundle)
	att := tekton_test.slsav1_attestation([clair_with_bundle, tpa_with_bundle])
	attestations := [att]
}

_manifests_both_vulns := object.union(_manifests, _tpa_manifests)

_blobs_both_vulns := object.union(_blobs, _tpa_blobs)

_mock_image_manifest_both_vulns(ref) := _manifests_both_vulns[ref]

_mock_blob_both_vulns(ref) := _blobs_both_vulns[ref]

test_name_function_with_missing_fields if {
	# Test _name with neither "name" nor "id" field
	vuln_no_name := {"severity": "HIGH"}
	assertions.assert_equal(cve._name(vuln_no_name), "UNKNOWN")

	# Test _name with "name" field (Clair format)
	vuln_with_name := {"name": "CVE-2024-1234"}
	assertions.assert_equal(cve._name(vuln_with_name), "CVE-2024-1234")

	# Test _name with "id" field (TPA format)
	vuln_with_id := {"id": "CVE-2024-5678"}
	assertions.assert_equal(cve._name(vuln_with_id), "CVE-2024-5678")
}

# TPA report mock data

_tpa_issue(id, severity, source, title) := {
	"id": id,
	"severity": severity,
	"source": source,
	"title": title,
}

_tpa_report := {"providers": {"rhtpa": {"sources": {
	"osv-github": {"dependencies": [{
		"ref": "pkg:golang/golang.org/x/text@v0.3.6",
		"issues": [
			_tpa_issue("CVE-2021-38561", "HIGH", "osv-github", "golang.org/x/text vulnerability"),
			_tpa_issue("CVE-2022-32149", "HIGH", "osv-github", "golang.org/x/text DoS vulnerability"),
		],
		"transitive": [],
	}]},
	"redhat-csaf": {"dependencies": [{
		"ref": "pkg:rpm/redhat/libcurl-minimal@8.12.1",
		"issues": [],
		"transitive": [
			{
				"ref": "pkg:rpm/redhat/pam-libs@1.6.1",
				"issues": [_tpa_issue("CVE-2025-6020", "HIGH", "redhat-csaf", "Linux-pam directory traversal")],
			},
			{
				"ref": "pkg:rpm/redhat/libnghttp2@1.64.0",
				"issues": [_tpa_issue("CVE-2026-27135", "HIGH", "redhat-csaf", "nghttp2 DoS")],
			},
		],
	}]},
}}}}

_tpa_manifests := {
	"registry.io/repository/image@sha256:tpa_report_digest": {"layers": [{
		"mediaType": "application/vnd.redhat.tpa-report+json",
		"digest": "sha256:tpa_report_blob_digest",
	}]},
	"registry.io/repository/image@sha256:no_vulnerabilities_tpa_report_digest": {"layers": [{
		"mediaType": "application/vnd.redhat.tpa-report+json",
		"digest": "sha256:no_vulnerabilities_tpa_blob_digest",
	}]},
}

_tpa_blobs := {
	"registry.io/repository/image@sha256:tpa_report_blob_digest": json.marshal(_tpa_report),
	"registry.io/repository/image@sha256:no_vulnerabilities_tpa_blob_digest": json.marshal({"providers": {}}),
}

_mock_tpa_image_manifest(ref) := _tpa_manifests[ref]

_mock_tpa_blob(ref) := _tpa_blobs[ref]

_tpa_attestations := _attestations_with_tpa_reports({"sha256:image_digest": "sha256:tpa_report_digest"})

_attestations_with_tpa_reports(reports) := attestations if {
	slsav1_task_with_result := tekton_test.resolved_slsav1_task("tpa-scan", [], [{
		"name": cve._reports_result_name,
		"type": "string",
		"value": reports,
	}])

	att1 := lib_test.att_mock_helper_ref(
		cve._reports_result_name,
		reports,
		"tpa-scan",
		_bundle,
	)

	task_with_bundle := tekton_test.with_bundle(slsav1_task_with_result, _bundle)
	att2 := tekton_test.slsav1_attestation([task_with_bundle])
	attestations := [att1, att2]
}
