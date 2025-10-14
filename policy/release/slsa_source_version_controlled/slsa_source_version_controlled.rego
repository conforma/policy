#
# METADATA
# title: SLSA - Source - Version Controlled
# description: >-
#   The SLSA requirement states the following:
#
#   "Every change to the source is tracked in a version control system
#   that meets the following requirements:
#
#     [Change history] There exists a record of the history of changes
#     that went into the revision. Each change must contain: the
#     identities of the uploader and reviewers (if any), timestamps of
#     the reviews (if any) and submission, the change
#     description/justification, the content of the change, and the
#     parent revisions.
#
#     [Immutable reference] There exists a way to indefinitely reference
#     this particular, immutable revision. In git, this is the {repo URL +
#     branch/tag/ref + commit ID}.
#
#   Most popular version control system meet this requirement, such as git,
#   Mercurial, Subversion, or Perforce."
#
#   This package verifies the requirement by asserting the image was built
#   from a git repository.
#
package slsa_source_version_controlled

import rego.v1

import data.lib

# METADATA
# title: Materials have uri and digest
# description: >-
#   Confirm at least one entry in the predicate.materials array of the attestation contains
#   the expected attributes: uri and digest.sha1.
# custom:
#   short_name: materials_format_okay
#   failure_msg: No materials match expected format
#   solution: >-
#     Make sure the attestation contains the repository URI and digest.sha1. This information
#     comes from the 'CHAINS-GIT_URL' and 'CHAINS-GIT_COMMIT' results in the 'git-clone' task.
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	count(lib.pipelinerun_attestations) > 0
	count(materials) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Material uri is a git repo
# description: >-
#   Ensure each entry in the predicate.materials array with a SHA-1 digest includes
#   a valid Git URI.
# custom:
#   short_name: materials_uri_is_git_repo
#   failure_msg: Material URI %q is not a git URI
#   solution: >-
#     Ensure the URI associated with a SHA-1 digest in the materials section
#     of the attestation is valid. This URI is derived from the 'CHAINS-GIT_URL' output
#     of the 'git-clone' task.
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some material in materials
	not startswith(material.uri, "git+")
	result := lib.result_helper(rego.metadata.chain(), [material.uri])
}

# METADATA
# title: Materials include git commit shas
# description: >-
#   Ensure that each entry in the predicate.materials array with a SHA-1 digest includes
#   a valid Git commit SHA.
# custom:
#   short_name: materials_include_git_sha
#   failure_msg: Material digest %q is not a git commit sha
#   solution: >-
#     Ensure the digest.sha1 in the materials section of the attestation is a valid
#     Git commit SHA. This commit information is derived from the 'CHAINS-GIT_COMMIT'
#     output of the 'git-clone' task.
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   - redhat_rpms
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some material in materials
	commit := material.digest.sha1
	not regex.match(`^[a-f0-9]{40}$`, commit)
	result := lib.result_helper(rego.metadata.chain(), [commit])
}

materials contains material if {
	some attestation in lib.pipelinerun_attestations
	some material in attestation.statement.predicate.materials
	material.uri
	material.digest.sha1
}

materials contains material if {
	some attestation in lib.pipelinerun_attestations
	some material in attestation.statement.predicate.buildDefinition.resolvedDependencies
	material.uri
	material.digest.sha1
}
