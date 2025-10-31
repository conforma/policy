package cve_test

import rego.v1

import data.cve
import data.lib
import data.lib.tekton_test
import data.lib.time as lib_time
import data.lib_test

test_success if {
	lib.assert_empty(cve.deny | cve.warn) with input.attestations as _no_vuln_attestations
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
}

test_success_with_rule_data if {
	lib.assert_empty(cve.deny | cve.warn) with input.attestations as _with_vuln_attestations
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

	lib.assert_equal_results(cve.deny, expected_deny) with input.attestations as _with_vuln_attestations
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

	lib.assert_equal_results(cve.deny, expected) with input.attestations as _with_vuln_attestations
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
	lib.assert_equal_results_no_collections(cve.deny, expected_deny) with input.attestations as _with_vuln_attestations
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
	lib.assert_equal_results_no_collections(cve.deny, expected_deny) with input.attestations as _with_vuln_attestations
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

	lib.assert_equal_results(cve.warn, expected) with input.attestations as _with_vuln_attestations
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

	lib.assert_equal_results(cve.warn, expected) with input.attestations as _with_vuln_attestations
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
		"msg": "Clair CVE scan results were not found",
	}}

	lib.assert_equal_results(cve.deny, expected) with input.image.ref as ref
		with ec.oci.descriptor as descriptor

	lib.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
		with input.image.ref as ref
		with ec.oci.descriptor as descriptor
		with ec.oci.image_manifest as null
	lib.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
		with input.image.ref as ref
		with ec.oci.descriptor as descriptor
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as null

	lib.assert_empty(cve.warn) with input.attestations as _no_vuln_attestations
		with input.image.ref as ref
		with ec.oci.descriptor as descriptor
		with ec.oci.image_manifest as null
	lib.assert_empty(cve.warn) with input.attestations as _no_vuln_attestations
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

	lib.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
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

	lib.assert_equal_results(cve.deny, expected) with input.attestations as _no_vuln_attestations
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

_clair_report := {"vulnerabilities": object.union(vulnerabilities, unpatched_vulnerabilities)}

_manifests := {
	"registry.io/repository/image@sha256:report_digest": {"layers": [{
		"mediaType": cve._report_oci_mime_type,
		"digest": "sha256:report_blob_digest",
	}]},
	"registry.io/repository/image@sha256:no_vulnerabilities_report_digest": {"layers": [{
		"mediaType": cve._report_oci_mime_type,
		"digest": "sha256:no_vulnerabilities_report_blob_digest",
	}]},
}

_blobs := {
	"registry.io/repository/image@sha256:report_blob_digest": json.marshal(_clair_report),
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
	att2 := tekton_test.slsav1_attestation([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)])
	attestations := [att1, att2]
}
