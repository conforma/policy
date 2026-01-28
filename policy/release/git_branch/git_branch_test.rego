package git_branch_test

import data.git_branch
import data.lib
import rego.v1

single_test_case(branch, expected_results) if {
	# regal ignore:line-length
	mock_input := {"attestations": [{"statement": {"predicate": {"buildConfig": {"tasks": [{"invocation": {"environment": {"annotations": {"build.appstudio.redhat.com/target_branch": branch}}}}]}}}}]}

	mock_rule_data := ["^c10s$", "^rhel-10.[0-9]+$", "^rhel-[0-9]+-main$", "branch[0-9]+-rhel-[0-9]+.[0-9]+.[0-9]+$"]

	mock_tasks := mock_input.attestations[0].statement.predicate.buildConfig.tasks

	# regal ignore:with-outside-test-context
	lib.assert_equal_results(expected_results, git_branch.deny) with input as mock_input
		# regal ignore:with-outside-test-context
with 		lib.rule_data as mock_rule_data
		# regal ignore:with-outside-test-context
with 		lib.tasks_from_pipelinerun as mock_tasks
}

test_allow_with_main_branch if {
	single_test_case("rhel-9-main", [])
}

test_allow_with_release_branch if {
	single_test_case("rhel-10.1", [])
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
