package github_certificate_test

import rego.v1

import data.github_certificate

import data.lib.assertions

test_all_good if {
	signatures := [{"certificate": good_cert}]
	assertions.assert_empty(github_certificate.deny) with input.image.signatures as signatures
	assertions.assert_empty(github_certificate.warn) with input.image.signatures as signatures
}

test_at_least_one_good if {
	signatures := [{"certificate": good_cert}, {"certificate": bad_cert}]
	assertions.assert_empty(github_certificate.deny) with input.image.signatures as signatures
	assertions.assert_empty(github_certificate.warn) with input.image.signatures as signatures
}

test_gh_workflow_repository_match if {
	signatures := [{"certificate": good_cert}]
	assertions.assert_empty(github_certificate.deny) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_repos as ["spam", "lcarva/festoji", "eggs"]
}

test_gh_workflow_repository_mismatch if {
	signatures := [{"certificate": good_cert}]
	expected := {{
		"code": "github_certificate.gh_workflow_repository",
		"msg": "Repository \"lcarva/festoji\" not in allowed list: [\"cli\", \"policy\"]",
	}}
	assertions.assert_equal_results(github_certificate.deny, expected) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_repos as ["cli", "policy"]
}

test_gh_workflow_ref_match if {
	signatures := [{"certificate": good_cert}]
	assertions.assert_empty(github_certificate.deny) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_refs as ["refs/heads/master", "refs/heads/main"]
}

test_gh_workflow_ref_mismatch if {
	signatures := [{"certificate": good_cert}]
	expected := {{
		"code": "github_certificate.gh_workflow_ref",
		"msg": "Ref \"refs/heads/master\" not in allowed list: [\"refs/heads/prod\"]",
	}}
	assertions.assert_equal_results(github_certificate.deny, expected) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_refs as ["refs/heads/prod"]
}

test_gh_workflow_name_match if {
	signatures := [{"certificate": good_cert}]
	assertions.assert_empty(github_certificate.deny) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_names as ["Package"]
}

test_gh_workflow_name_mismatch if {
	signatures := [{"certificate": good_cert}]
	expected := {{
		"code": "github_certificate.gh_workflow_name",
		"msg": "Name \"Package\" not in allowed list: [\"hackery\"]",
	}}
	assertions.assert_equal_results(github_certificate.deny, expected) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_names as ["hackery"]
}

test_gh_workflow_trigger_match if {
	signatures := [{"certificate": good_cert}]
	assertions.assert_empty(github_certificate.deny) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_triggers as ["push"]
}

test_gh_workflow_trigger_mismatch if {
	signatures := [{"certificate": good_cert}]
	expected := {{
		"code": "github_certificate.gh_workflow_trigger",
		"msg": "Trigger \"push\" not in allowed list: [\"build\"]",
	}}
	assertions.assert_equal_results(github_certificate.deny, expected) with input.image.signatures as signatures
		with data.rule_data.allowed_gh_workflow_triggers as ["build"]
}

# regal ignore:rule-length
test_missing_extensions if {
	expected := {
		{
			"code": "github_certificate.gh_workflow_extensions",
			"msg": "Missing extension \"GitHub Workflow Name\"",
		},
		{
			"code": "github_certificate.gh_workflow_extensions",
			"msg": "Missing extension \"GitHub Workflow Ref\"",
		},
		{
			"code": "github_certificate.gh_workflow_extensions",
			"msg": "Missing extension \"GitHub Workflow Repository\"",
		},
		{
			"code": "github_certificate.gh_workflow_extensions",
			"msg": "Missing extension \"GitHub Workflow SHA\"",
		},
		{
			"code": "github_certificate.gh_workflow_extensions",
			"msg": "Missing extension \"GitHub Workflow Trigger\"",
		},
	}
	assertions.assert_equal_results(github_certificate.warn, expected)
	assertions.assert_equal_results(github_certificate.warn, expected) with input as {}
	assertions.assert_equal_results(github_certificate.warn, expected) with input.image as {}
	assertions.assert_equal_results(github_certificate.warn, expected) with input.image.signatures as []
	assertions.assert_equal_results(github_certificate.warn, expected) with input.image.signatures as [{}]
	assertions.assert_equal_results(github_certificate.warn, expected) with input.image.signatures as [{"certificate": ""}]
	assertions.assert_equal_results(github_certificate.warn, expected) with input.image.signatures as [{"certificate": bad_cert}]
}

test_rule_data_provided if {
	d := {
		"allowed_gh_workflow_repos": [
			# Wrong type
			1,
			# Duplicated items
			"lcarva/festoji",
			"lcarva/festoji",
		],
		# We don't need to check the different errors for each key as they are processed the same
		# way. But we do want to, at least, verify a single error.
		"allowed_gh_workflow_refs": [1, "refs/heads/master"],
		"allowed_gh_workflow_names": [1, "Package"],
		"allowed_gh_workflow_triggers": [1, "push"],
	}

	expected := {
		{
			"code": "github_certificate.rule_data_provided",
			"msg": "Rule data allowed_gh_workflow_repos has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "github_certificate.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_gh_workflow_repos has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "github_certificate.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_gh_workflow_refs has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "github_certificate.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_gh_workflow_names has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "github_certificate.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_gh_workflow_triggers has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	signatures := [{"certificate": good_cert}]
	assertions.assert_equal_results(github_certificate.deny, expected) with data.rule_data as d
		with input.image.signatures as signatures
}

# This is a certificate used when signing an image on GitHub. It
# contains all the expected Fulcio GitHub extensions.
good_cert := `-----BEGIN CERTIFICATE-----
MIIGgjCCBgigAwIBAgIUQNGRo7U3odD/NCO2AUOUZEHrrV4wCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjMwNjIzMjAwODM4WhcNMjMwNjIzMjAxODM4WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEF9tc9f4G+uPc23aEzS519jAjnzavr4wL0Cx5
Zs4Khd9kcHONFZE1JFHmUICjP6BafRZ3cWz8yv35paQVSV+DVKOCBScwggUjMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUnDhg
2f/e4XFEns+m+PltKUbHHf4wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wYAYDVR0RAQH/BFYwVIZSaHR0cHM6Ly9naXRodWIuY29tL2xjYXJ2YS9mZXN0
b2ppLy5naXRodWIvd29ya2Zsb3dzL3BhY2thZ2UueWFtbEByZWZzL2hlYWRzL21h
c3RlcjA5BgorBgEEAYO/MAEBBCtodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVi
dXNlcmNvbnRlbnQuY29tMBIGCisGAQQBg78wAQIEBHB1c2gwNgYKKwYBBAGDvzAB
AwQoODQ4ZWRjNDUyY2NiYzZkNDJlYzU2YzI4MDdlZWYyZjQ5ZTc1NGM1ZTAVBgor
BgEEAYO/MAEEBAdQYWNrYWdlMBwGCisGAQQBg78wAQUEDmxjYXJ2YS9mZXN0b2pp
MB8GCisGAQQBg78wAQYEEXJlZnMvaGVhZHMvbWFzdGVyMDsGCisGAQQBg78wAQgE
LQwraHR0cHM6Ly90b2tlbi5hY3Rpb25zLmdpdGh1YnVzZXJjb250ZW50LmNvbTBi
BgorBgEEAYO/MAEJBFQMUmh0dHBzOi8vZ2l0aHViLmNvbS9sY2FydmEvZmVzdG9q
aS8uZ2l0aHViL3dvcmtmbG93cy9wYWNrYWdlLnlhbWxAcmVmcy9oZWFkcy9tYXN0
ZXIwOAYKKwYBBAGDvzABCgQqDCg4NDhlZGM0NTJjY2JjNmQ0MmVjNTZjMjgwN2Vl
ZjJmNDllNzU0YzVlMB0GCisGAQQBg78wAQsEDwwNZ2l0aHViLWhvc3RlZDAxBgor
BgEEAYO/MAEMBCMMIWh0dHBzOi8vZ2l0aHViLmNvbS9sY2FydmEvZmVzdG9qaTA4
BgorBgEEAYO/MAENBCoMKDg0OGVkYzQ1MmNjYmM2ZDQyZWM1NmMyODA3ZWVmMmY0
OWU3NTRjNWUwIQYKKwYBBAGDvzABDgQTDBFyZWZzL2hlYWRzL21hc3RlcjAZBgor
BgEEAYO/MAEPBAsMCTE1OTA2OTgzMjApBgorBgEEAYO/MAEQBBsMGWh0dHBzOi8v
Z2l0aHViLmNvbS9sY2FydmEwFwYKKwYBBAGDvzABEQQJDAc1MjcyOTMxMGIGCisG
AQQBg78wARIEVAxSaHR0cHM6Ly9naXRodWIuY29tL2xjYXJ2YS9mZXN0b2ppLy5n
aXRodWIvd29ya2Zsb3dzL3BhY2thZ2UueWFtbEByZWZzL2hlYWRzL21hc3RlcjA4
BgorBgEEAYO/MAETBCoMKDg0OGVkYzQ1MmNjYmM2ZDQyZWM1NmMyODA3ZWVmMmY0
OWU3NTRjNWUwFAYKKwYBBAGDvzABFAQGDARwdXNoMFQGCisGAQQBg78wARUERgxE
aHR0cHM6Ly9naXRodWIuY29tL2xjYXJ2YS9mZXN0b2ppL2FjdGlvbnMvcnVucy81
MzYwMTI1NjEzL2F0dGVtcHRzLzEwgYkGCisGAQQB1nkCBAIEewR5AHcAdQDdPTBq
xscRMmMZHhyZZzcCokpeuN48rf+HinKALynujgAAAYjp34D6AAAEAwBGMEQCIEDf
e5O+p+0QdfRbRY4U5hJG+REG3Xxci78SBp8iuJEpAiAI6in8wxrfiC8reu0+EoFc
wX2Ep4RzIYkAy+p2Ga6JvTAKBggqhkjOPQQDAwNoADBlAjB+CXmTANUemgjXL2/X
nVIP9B+/02qr8N3kBIPV91VvuCbSMv0mqFImYX+cRxsuVtYCMQDd2NVxH0x5ErBU
s/UT5EA4t34N1UcRRHfF3YPLPzIvgEYdg0sn3qmgABlPCr1BOkY=
-----END CERTIFICATE-----`

# This is just a random certificate that does not contain any of
# the Fulcio GitHub extensions.
bad_cert := `-----BEGIN CERTIFICATE-----
MIIB8TCCAXegAwIBAgIUBHcWnSa4N1K+z/dRDitfwGT6RUowCgYIKoZIzj0EAwMw
MzETMBEGA1UECgwKZm9vYmFyLmRldjEcMBoGA1UEAwwTZm9vYmFyLWludGVybWVk
aWF0ZTAeFw05MDAxMDEwMDAwMDBaFw00MDAxMDEwMDAwMDBaMAAwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARSG+kx7P0C96xegjJgg81uJrJf/G+yYLRKucwP3AMP
Q1xFB+/8wdUqeTLZPI7AsmcGtvbT/Vr5GRPNT1NUSlFVo4GbMIGYMB0GA1UdDgQW
BBTXA23F2RNNOlWky1b9MQ1AX3NfQzAfBgNVHSMEGDAWgBSRLp/yACH4u5DoQ1HD
pNZpq/1mazAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMwMQYD
VR0RBCowKIYRaHR0cDovL2Zvb2Jhci5kZXagEwYKKwYBBAGDvzABB6AFDANGT08w
CgYIKoZIzj0EAwMDaAAwZQIwWi7Kx/jf8O3riw+dLxK2p4+JPbH92aFrq3WozDex
iXb1ZTM3FhaFFrM15gMKWlVhAjEAig8qoM7nW0cPq0x029VvJPjm4knz7ZvmnY3d
VwmStvcPrB+2+tmxDfK1BKl1v5/Z
-----END CERTIFICATE-----`
