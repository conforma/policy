#
# METADATA
# title: Git branch checks
# description: >-
#   Check that the build has an expected target git branch. The
#   specific branches permitted are specified as a list of regexes
#   in the `allowed_target_branch_patterns` rule data.
#
package git_branch

import data.lib
import rego.v1

# METADATA
# title: Builds have a trusted target branch
# description: Build must target a configured branch pattern (e.g., 'c10s')
# custom:
#   short_name: git_branch
#   failure_msg: Build target is %s which is not a trusted target branch
#   collections:
#   - redhat_rpms
#   effective_on: 2025-07-01
deny contains result if {
	some task in lib.tasks_from_pipelinerun

	# Note that we're assuming that the annotation exists.
	# This will not produce a violation if the annotation is missing
	branch := task.invocation.environment.annotations["build.appstudio.redhat.com/target_branch"]
	not matches_any(branch)
	result := lib.result_helper(rego.metadata.chain(), [branch])
}

matches_any(branch) if {
	some pattern in lib.rule_data("allowed_target_branch_patterns")
	regex.match(pattern, branch)
}
