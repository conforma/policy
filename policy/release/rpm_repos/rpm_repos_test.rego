package rpm_repos_test

import rego.v1

import data.lib.utils
import data.lib
import data.lib.sbom
import data.rpm_repos

test_repo_id_data_empty if {
	expected := {
		"code": "rpm_repos.rule_data_provided",
		"msg": "Rule data 'known_rpm_repositories' has unexpected format: (Root): Array must have at least 1 items",
		"severity": "failure",
	}

	utils.assert_equal_results({expected}, rpm_repos.deny) with data.rule_data.known_rpm_repositories as []
}

test_repo_id_data_not_an_array if {
	expected := {
		"code": "rpm_repos.rule_data_provided",
		"msg": sprintf("%s %s", [
			"Rule data 'known_rpm_repositories' has unexpected format:",
			"(Root): Invalid type. Expected: array, given: object",
		]),
		"severity": "failure",
	}

	utils.assert_equal_results({expected}, rpm_repos.deny) with data.rule_data.known_rpm_repositories as {"chunky": "bacon"}
}

test_repo_id_data_not_strings if {
	expected := {
		"code": "rpm_repos.rule_data_provided",
		"msg": "Rule data 'known_rpm_repositories' has unexpected format: 1: Invalid type. Expected: string, given: integer",
		"severity": "failure",
	}

	utils.assert_equal_results({expected}, rpm_repos.deny) with data.rule_data.known_rpm_repositories as ["spam", 42]
}

test_repo_id_all if {
	utils.assert_equal(
		{p1, p2, p3, p4, p5, p7},
		rpm_repos.all_c2_rpm_purls,
	) with lib.sbom.all_sboms as fake_cyclonedx_sboms

	utils.assert_equal(
		{p1, p2, p3, p4, p5, p7},
		rpm_repos.all_c2_rpm_purls,
	) with lib.sbom.all_sboms as fake_spdx_sboms
}

test_repo_id_all_with_repo_id if {
	utils.assert_equal(
		{p1, p2, p3, p7},
		rpm_repos._plain_purls(rpm_repos.all_c2_purls_with_repo_ids),
	) with lib.sbom.all_sboms as fake_cyclonedx_sboms

	utils.assert_equal(
		{p1, p2, p3, p7},
		rpm_repos._plain_purls(rpm_repos.all_c2_purls_with_repo_ids),
	) with lib.sbom.all_sboms as fake_spdx_sboms
}

test_repo_id_all_known if {
	utils.assert_equal(
		{p1, p2, p7},
		rpm_repos._plain_purls(rpm_repos.all_c2_purls_with_known_repo_ids),
	) with lib.sbom.all_sboms as fake_cyclonedx_sboms with data.rule_data.known_rpm_repositories as fake_repo_id_list

	utils.assert_equal(
		{p1, p2, p7},
		rpm_repos._plain_purls(rpm_repos.all_c2_purls_with_known_repo_ids),
	) with lib.sbom.all_sboms as fake_spdx_sboms with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_repo_id_all_known_with_extras if {
	rule_data := {
		"known_rpm_repositories": array.slice(fake_repo_id_list, 1, count(fake_repo_id_list)),
		"extra_rpm_repositories": array.slice(fake_repo_id_list, 0, 1),
	}
	utils.assert_equal(
		{p1, p2, p7},
		rpm_repos._plain_purls(rpm_repos.all_c2_purls_with_known_repo_ids),
	) with lib.sbom.all_sboms as fake_cyclonedx_sboms with data.rule_data as rule_data

	utils.assert_equal(
		{p1, p2, p7},
		rpm_repos._plain_purls(rpm_repos.all_c2_purls_with_known_repo_ids),
	) with lib.sbom.all_sboms as fake_spdx_sboms with data.rule_data as rule_data
}

test_repo_id_purls_missing_repo_ids if {
	expected := {
		{
			"code": "rpm_repos.ids_known",
			"msg": sprintf("%s %s", [
				"RPM repo id check failed: An RPM component in the SBOM did not specify a repository_id value in its purl:",
				"pkg:rpm/redhat/spam@1.2.3?arch=amd64&pastry_id=puff",
			]),
			"term": "pkg:rpm/redhat/spam@1.2.3?arch=amd64&pastry_id=puff",
		},
		{
			"code": "rpm_repos.ids_known",
			"msg": sprintf("%s %s", [
				"RPM repo id check failed: An RPM component in the SBOM did not specify a repository_id value in its purl:",
				"pkg:rpm/borken",
			]),
			"term": "pkg:rpm/borken",
		},
	}

	cyclonedx_sboms := [fake_cyclonedx_sbom({p1, p2, p4, p5, p6, p7})]
	utils.assert_equal_results(expected, rpm_repos.deny) with lib.sbom.all_sboms as cyclonedx_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list

	spdx_sboms := [fake_spdx_sbom({p1, p2, p4, p5, p6, p7})]
	utils.assert_equal_results(expected, rpm_repos.deny) with lib.sbom.all_sboms as spdx_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_repo_id_purls_missing_repo_ids_truncated if {
	expected := {{
		"code": "rpm_repos.ids_known",
		# regal ignore:line-length
		"msg": "RPM repo id check failed: An RPM component in the SBOM did not specify a repository_id value in its purl: pkg:rpm/borken (1 additional similar violations not separately listed)",
		"term": "pkg:rpm/borken",
	}}

	cyclonedx_sboms := [fake_cyclonedx_sbom({p1, p2, p4, p5, p6})]
	utils.assert_equal_results(expected, rpm_repos.deny) with lib.sbom.all_sboms as cyclonedx_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
		with rpm_repos._truncate_threshold as 1 with rpm_repos._min_remainder_count as 0

	spdx_sboms := [fake_spdx_sbom({p1, p2, p4, p5, p6})]
	utils.assert_equal_results(expected, rpm_repos.deny) with lib.sbom.all_sboms as spdx_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
		with rpm_repos._truncate_threshold as 1 with rpm_repos._min_remainder_count as 0
}

test_repo_id_purls_unknown_repo_ids if {
	expected := {
		"code": "rpm_repos.ids_known",
		"msg": sprintf("%s %s", [
			"RPM repo id check failed: An RPM component in the SBOM specified an unknown or disallowed repository_id:",
			"pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-unrecognized-2-rpms",
		]),
		"term": "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-unrecognized-2-rpms",
	}

	cyclonedx_sboms := [fake_cyclonedx_sbom({p1, p2, p3, p6})]
	utils.assert_equal_results({expected}, rpm_repos.deny) with lib.sbom.all_sboms as cyclonedx_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list

	spdx_sboms := [fake_spdx_sbom({p1, p2, p3, p6})]
	utils.assert_equal_results({expected}, rpm_repos.deny) with lib.sbom.all_sboms as spdx_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_purl_in_multiple_sboms if {
	# Same PURL in both CycloneDX and SPDX SBOMs emits a single violation.
	expected := {
		"code": "rpm_repos.ids_known",
		"msg": sprintf("%s %s", [
			"RPM repo id check failed: An RPM component in the SBOM specified an unknown or disallowed repository_id:",
			"pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-unrecognized-2-rpms",
		]),
		"term": "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-unrecognized-2-rpms",
	}

	all_sboms := [fake_cyclonedx_sbom({p1, p2, p3, p6}), fake_spdx_sbom({p1, p2, p3, p6})]
	utils.assert_equal_results({expected}, rpm_repos.deny) with lib.sbom.all_sboms as all_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_repo_id_happy_path_cachi2_components if {
	# These three purls are valid, so we see no violations
	all_sboms := [fake_cyclonedx_sbom({p1, p2, p7}), fake_spdx_sbom({p1, p2, p7})]
	utils.assert_empty(rpm_repos.deny) with rpm_repos._all_sboms as all_sboms
		with data.rule_data.known_rpm_repositories as fake_repo_id_list
}

test_repo_id_happy_path_syft_components if {
	# All the rpm components are ignored because they were not generated by cachi2, so we see no violations
	utils.assert_empty(rpm_repos.deny) with rpm_repos._all_sboms as fake_sboms_syft
		with data.rule_data.known_rpm_repositories as fake_repo_id_list

	# Notice the rule data doesn't make a difference
	utils.assert_empty(rpm_repos.deny) with rpm_repos._all_sboms as fake_sboms_syft
		with data.rule_data.known_rpm_repositories as ["pancakes"]
}

test_clamp_violation_strings if {
	utils.assert_equal(
		{"remainder": 2, "values": ["a", "b", "c"]},
		rpm_repos._truncate(["a", "b", "c", "d", "e"]),
	) with rpm_repos._truncate_threshold as 3 with rpm_repos._min_remainder_count as 0

	utils.assert_equal(
		{"remainder": 0, "values": ["a", "b", "c", "d", "e"]},
		rpm_repos._truncate(["a", "b", "c", "d", "e"]),
	) with rpm_repos._truncate_threshold as 5

	utils.assert_equal(
		{"remainder": 3, "values": ["a", "b"]},
		rpm_repos._truncate(["a", "b", "c", "d", "e"]),
	) with rpm_repos._truncate_threshold as 2 with rpm_repos._min_remainder_count as 3
}

fake_cyclonedx_sboms := [fake_cyclonedx_sbom({p1, p2, p3, p4, p5, p6, p7})]

fake_cyclonedx_sbom(fake_purls) := {"components": [
{
	"purl": p,
	"properties": [sbom._cachi2_found_by_property("hermeto")],
} |
	some p in fake_purls
]}

fake_sboms_syft := [
	fake_sbom_cyclonedx_found_by_syft({p1, p2, p3, p4, p5, p6, p7}),
	fake_sbom_spdx_found_by_syft({p1, p2, p3, p4, p5, p6, p7}),
]

fake_sbom_cyclonedx_found_by_syft(fake_purls) := {"components": [
{
	"purl": p,
	# It's not specially relevant to the functionality, since we look for the cachi2 property
	# and ignore everything else, but this is what we see syft produce for rpm components.
	"properties": [{"name": "syft:package:foundBy", "value": "rpm-db-cataloger"}],
} |
	some p in fake_purls
]}

fake_sbom_spdx_found_by_syft(fake_purls) := {"packages": [
{
	"annotations": [{"annotator": "syft", "annotationType": "OTHER"}],
	"externalRefs": [r],
} |
	some p in fake_purls
	r := {
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": p,
	}
]}

fake_spdx_sboms := [fake_spdx_sbom({p1, p2, p3, p4, p5, p6, p7})]

fake_spdx_sbom(fake_purls) := {"packages": [
{
	"annotations": [{"annotator": "Tool: cachi2:jsonencoded", "annotationType": "OTHER"}],
	"externalRefs": [r],
} |
	some p in fake_purls
	r := {
		"referenceType": "purl",
		"referenceCategory": "PACKAGE-MANAGER",
		"referenceLocator": p,
	}
]}

fake_repo_id_list := [
	"rhel-23-for-spam-9-rpms",
	"rhel-42-for-bacon-12-rpms",
	"rhel-8-for-x86_64-appstream-eus-rpms__8_DOT_6",
]

p1 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-for-spam-9-rpms"

p2 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-42-for-bacon-12-rpms"

p3 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&repository_id=rhel-23-unrecognized-2-rpms"

p4 := "pkg:rpm/redhat/spam@1.2.3?arch=amd64&pastry_id=puff"

p5 := "pkg:rpm/borken"

p6 := "pkg:golang/gitplanet.com/bacon@1.2.3?arch=amd64"

# regal ignore:line-length
p7 := "pkg:rpmmod/redhat/squid@4%3A8040020210420090912%3A522a0ee4?arch=ppc64le&repository_id=rhel-8-for-x86_64-appstream-eus-rpms__8_DOT_6"
