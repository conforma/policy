package git_branch_test

import data.lib.assertions

import data.git_branch

import data.lib
import data.lib.rule_data
import rego.v1

single_test_case(branch, expected_results) if {
	# regal ignore:line-length
	mock_input := {"attestations": [{"statement": {"predicate": {"buildConfig": {"tasks": [{"invocation": {"environment": {"annotations": {"build.appstudio.redhat.com/target_branch": branch}}}}]}}}}]}

	mock_rule_data := [
		"^c[0-9]+s$",
		"^rhel-10\\.[0-9]+$",
		"^rhel-[0-9]+\\.[0-9]\\.0$",
		"^rhel-[0-9]+-main$",
		"branch[0-9]+-rhel-[0-9]+.[0-9]+.[0-9]+$",
	]

	mock_tasks := mock_input.attestations[0].statement.predicate.buildConfig.tasks

	# regal ignore:with-outside-test-context
	assertions.assert_equal_results(expected_results, git_branch.deny) with input as mock_input
		# regal ignore:with-outside-test-context
with 		rule_data.get as mock_rule_data
		# regal ignore:with-outside-test-context
with 		lib.tasks_from_pipelinerun as mock_tasks
}

test_allow_with_main_branch if {
	single_test_case("rhel-9-main", [])
}

test_allow_with_release_branch if {
	single_test_case("rhel-10.1.0", [])
}

test_allow_with_c10s_branch if {
	single_test_case("c10s", [])
}

test_allow_with_hotfixbranch if {
	single_test_case("kernel-5.14.0-570.42.1.el9_6-branch1-rhel-9.6.0", [])
	single_test_case("kernel-5.14.0-570.42.1.el9_6-branch1-rhel-9.6.0", [])
	single_test_case("kernel-5.14.0-570.42.1.el10_3-branch1-rhel-10.3.1", [])
	single_test_case("kernel-5.14.0-570.42.1.el11_2-branch13-rhel-11.2.9", [])
}

test_deny_with_disallowed_branch if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is feature-branch which is not a trusted target branch",
	}}
	single_test_case("feature-branch", expected)
}

test_deny_with_unmatched_branch if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is release-1 which is not a trusted target branch",
	}}
	single_test_case("release-1", expected)
}

# Tests for ^c[0-9]+s$ regex pattern
test_c_stream_single_digit if {
	single_test_case("c1s", [])
	single_test_case("c9s", [])
}

test_c_stream_multi_digit if {
	single_test_case("c10s", [])
	single_test_case("c100s", [])
	single_test_case("c999s", [])
}

test_c_stream_no_digits_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is cs which is not a trusted target branch",
	}}
	single_test_case("cs", expected)
}

test_c_stream_no_s_suffix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is c10 which is not a trusted target branch",
	}}
	single_test_case("c10", expected)
}

test_c_stream_double_s_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is c10ss which is not a trusted target branch",
	}}
	single_test_case("c10ss", expected)
}

test_c_stream_with_prefix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is xc10s which is not a trusted target branch",
	}}
	single_test_case("xc10s", expected)
}

test_c_stream_with_suffix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is c10s-beta which is not a trusted target branch",
	}}
	single_test_case("c10s-beta", expected)
}

test_c_stream_uppercase_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is C10S which is not a trusted target branch",
	}}
	single_test_case("C10S", expected)
}

test_rhel_version_multi_digit_major_no_patch if {
	single_test_case("rhel-10.1", [])
}

# Tests for ^rhel-[0-9]+\.[0-9](\.[0-9])?$ regex pattern - with patch version
test_rhel_version_single_digit_major_minor_patch if {
	single_test_case("rhel-8.0.0", [])
	single_test_case("rhel-9.9.0", [])
}

test_rhel_version_multi_digit_major_with_patch if {
	single_test_case("rhel-10.1.0", [])
	single_test_case("rhel-11.9.0", [])
}

test_rhel_version_no_minor_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-9 which is not a trusted target branch",
	}}
	single_test_case("rhel-9", expected)
}

test_rhel_version_multi_digit_minor_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-9.10 which is not a trusted target branch",
	}}
	single_test_case("rhel-9.10", expected)
}

test_rhel_version_multi_digit_patch_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-9.5.10 which is not a trusted target branch",
	}}
	single_test_case("rhel-9.5.10", expected)
}

test_rhel_version_extra_component_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-9.5.3.1 which is not a trusted target branch",
	}}
	single_test_case("rhel-9.5.3.1", expected)
}

test_rhel_version_with_suffix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-9.5-extra which is not a trusted target branch",
	}}
	single_test_case("rhel-9.5-extra", expected)
}

test_rhel_version_with_patch_suffix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-9.5.3-extra which is not a trusted target branch",
	}}
	single_test_case("rhel-9.5.3-extra", expected)
}

test_rhel_version_with_prefix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is feature-rhel-9.5 which is not a trusted target branch",
	}}
	single_test_case("feature-rhel-9.5", expected)
}

# Tests for ^rhel-[0-9]+-main$ regex pattern
test_rhel_main_single_digit_major if {
	single_test_case("rhel-9-main", [])
	single_test_case("rhel-8-main", [])
}

test_rhel_main_multi_digit_major if {
	single_test_case("rhel-10-main", [])
	single_test_case("rhel-11-main", [])
	single_test_case("rhel-99-main", [])
}

test_rhel_main_no_major_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-main which is not a trusted target branch",
	}}
	single_test_case("rhel-main", expected)
}

test_rhel_main_with_suffix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is rhel-9-main-branch which is not a trusted target branch",
	}}
	single_test_case("rhel-9-main-branch", expected)
}

test_rhel_main_with_prefix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is feature-rhel-9-main which is not a trusted target branch",
	}}
	single_test_case("feature-rhel-9-main", expected)
}

# Tests for branch[0-9]+-rhel-[0-9]+.[0-9]+.[0-9]+$ regex pattern
test_hotfix_branch_single_digit_branch_number if {
	single_test_case("kernel-5.14.0-570.42.1.el9_6-branch1-rhel-9.6.0", [])
	single_test_case("kernel-5.14.0-570.42.1.el10_3-branch2-rhel-10.3.1", [])
}

test_hotfix_branch_multi_digit_branch_number if {
	single_test_case("kernel-5.14.0-570.42.1.el9_6-branch13-rhel-9.6.9", [])
	single_test_case("kernel-5.14.0-570.42.1.el11_2-branch99-rhel-11.2.0", [])
}

test_hotfix_branch_multi_digit_versions if {
	single_test_case("package-1.2.3-branch1-rhel-10.10.10", [])
	single_test_case("package-1.2.3-branch1-rhel-99.99.99", [])
}

test_hotfix_branch_no_branch_number_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is kernel-5.14.0-570.42.1.el9_6-branch-rhel-9.6.0 which is not a trusted target branch",
	}}
	single_test_case("kernel-5.14.0-570.42.1.el9_6-branch-rhel-9.6.0", expected)
}

test_hotfix_branch_missing_patch_version_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is kernel-5.14.0-570.42.1.el9_6-branch1-rhel-9.6 which is not a trusted target branch",
	}}
	single_test_case("kernel-5.14.0-570.42.1.el9_6-branch1-rhel-9.6", expected)
}

test_hotfix_branch_with_extra_suffix_denied if {
	expected := {{
		"code": "git_branch.git_branch",
		"msg": "Build target is kernel-5.14.0-570.42.1.el9_6-branch1-rhel-9.6.0-extra which is not a trusted target branch",
	}}
	single_test_case("kernel-5.14.0-570.42.1.el9_6-branch1-rhel-9.6.0-extra", expected)
}
