#
# METADATA
# title: Pipeline definition Task bundle policies
# description: >-
#   To be able to reproduce and audit builds accurately it's important
#   to know exactly what happens during the build. To do this
#   Conforma requires that all tasks are defined in a set of
#   known and trusted task bundles. This package includes rules to
#   confirm that the tasks in a Pipeline definition are defined in task
#   bundles, and that the task bundles are from the list of known
#   and trusted bundles.
#
package task_bundle

import rego.v1

import data.lib
import data.lib.tekton

# =============================================================================
# MANIFEST PRE-FETCHING
# Collect all bundle references and fetch manifests in a single batch call.
# =============================================================================

# Collect all unique bundle references from tasks in the pipeline definition
_all_bundle_refs contains bundle if {
	some task in input.spec.tasks
	bundle := tekton.task_ref(task).bundle
	bundle != ""
}

# Batch fetch all manifests at once using ec.oci.image_manifests
# This returns a map of bundle_ref -> manifest
_manifests := ec.oci.image_manifests(_all_bundle_refs)

# =============================================================================

# METADATA
# title: Unpinned task bundle reference
# description: >-
#   Check if the Tekton Bundle used for the Tasks in the Pipeline definition
#   is pinned to a digest.
# custom:
#   short_name: unpinned_task_bundle
#   failure_msg: Pipeline task '%s' uses an unpinned task bundle reference '%s'
#
warn contains result if {
	some task in tekton.unpinned_task_bundle(input.spec.tasks)
	result := lib.result_helper(rego.metadata.chain(), [task.name, tekton.bundle(task)])
}

# METADATA
# title: Task bundle is out of date
# description: >-
#   For each Task in the Pipeline definition, check if the Tekton Bundle used is
#   the most recent.
# custom:
#   short_name: out_of_date_task_bundle
#   failure_msg: >-
#     Pipeline task '%s' uses an out of date task bundle '%s', new version of the
#     Task must be used before %s
#
warn contains result if {
	# only run if trusted_task_rules are empty
	# this can either go away when trusted_task_rules are fully implemented or we can take
	# a loook at it when versioning is implemented.
	tekton.missing_trusted_task_rules_data
	some task in input.spec.tasks
	expiry := tekton.expiry_of(task)
	bundle := tekton.bundle(task)
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundle, time.format(expiry)])
}

# METADATA
# title: Task bundle was not used or is not defined
# description: >-
#   Check for the existence of a task bundle. This rule will
#   fail if the task is not called from a bundle.
# custom:
#   short_name: disallowed_task_reference
#   failure_msg: Pipeline task '%s' does not contain a bundle reference
#
deny contains result if {
	some task in tekton.disallowed_task_reference(input.spec.tasks)
	result := lib.result_helper(rego.metadata.chain(), [task.name])
}

# METADATA
# title: Task bundle reference is empty
# description: >-
#   Check that a valid task bundle reference is being used.
# custom:
#   short_name: empty_task_bundle_reference
#   failure_msg: Pipeline task '%s' uses an empty bundle image reference
#
deny contains result if {
	some task in tekton.empty_task_bundle_reference(input.spec.tasks)
	result := lib.result_helper(rego.metadata.chain(), [task.name])
}

# METADATA
# title: Task bundle is not trusted
# description: >-
#   For each Task in the Pipeline definition, check if the Tekton Bundle used is a trusted task.
# custom:
#   short_name: untrusted_task_bundle
#   failure_msg: Pipeline task '%s' uses an untrusted task bundle '%s'
#
deny contains result if {
	some task in tekton.untrusted_task_refs(input.spec.tasks, _manifests)
	bundle := tekton.bundle(task)
	bundle != ""
	result := lib.result_helper(rego.metadata.chain(), [task.name, bundle])
}

# METADATA
# title: Missing required data
# description: >-
#   Confirm the `trusted_tasks` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: missing_required_data
#   failure_msg: Missing required trusted_tasks data
deny contains result if {
	tekton.missing_all_trusted_tasks_data
	result := lib.result_helper(rego.metadata.chain(), [])
}
