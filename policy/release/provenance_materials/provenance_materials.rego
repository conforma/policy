#
# METADATA
# title: Provenance Materials
# description: >-
#   This package provides rules for verifying the contents of the materials section
#   of the SLSA Provenance attestation.
#
package provenance_materials

import rego.v1

import data.lib
import data.lib.tekton

# METADATA
# title: Git clone task found
# description: >-
#   Confirm that the attestation contains a git-clone task with `commit` and `url` task results.
# custom:
#   short_name: git_clone_task_found
#   failure_msg: Task git-clone not found
#   solution: >-
#     Make sure the build pipeline contains a task named 'git-clone'.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	count(tekton.git_clone_tasks(attestation)) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Git clone source matches materials provenance
# description: >-
#   Confirm that the result of the git-clone task is included in the materials section of the SLSA
#   provenance attestation.
# custom:
#   short_name: git_clone_source_matches_provenance
#   failure_msg: Entry in materials for the git repo %q and commit %q not found
#   solution: >-
#     The build pipeline must contain a task named 'git-clone' and that task must emit
#     results named 'url' and 'commit' and contain the clone git repository and commit,
#     respectively.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - provenance_materials.git_clone_task_found
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations

	some task in tekton.git_clone_tasks(attestation)
	url := _normalize_git_url(tekton.task_result(task, "url"))
	commit := tekton.task_result(task, "commit")

	materials := [m |
		some m in attestation.statement.predicate.materials
		m.uri == url
		m.digest.sha1 == commit
	]
	count(materials) == 0

	result := lib.result_helper(rego.metadata.chain(), [url, commit])
}

_normalize_git_url(url) := _suffix_git_url(_prefix_git_url(url))

_prefix_git_url(url) := normalized if {
	prefix := "git+"
	not strings.any_prefix_match(url, prefix)
	normalized := concat("", [prefix, url])
} else := url

_suffix_git_url(url) := normalized if {
	suffix := ".git"
	not strings.any_suffix_match(url, suffix)
	normalized := concat("", [url, suffix])
} else := url
