#
# METADATA
# description: >-
#   This package contains a rule to ensure that each task in the image's
#   build pipeline ran using a container image from a known and presumably
#   trusted source.
#
package policy.release.step_image_registries

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib
import data.lib.tkn

# METADATA
# title: Task steps ran on permitted container images
# description: >-
#   Confirm that each step in each TaskRun ran on a container image with a url that
#   matches one of the prefixes in the provided list of allowed step image registry
#   prefixes.
# custom:
#   short_name: task_step_images_permitted
#   failure_msg: Step %d in task '%s' has disallowed image ref '%s'
#   solution: >-
#     Make sure the container image used in each step of the build pipeline comes from
#     an approved registry. The approved list is under 'allowed_step_image_registry_prefixes'
#     in the xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources].
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some task in lib.tasks_from_pipelinerun
	some step_index, step in tkn.task_steps(task)
	image_ref := tkn.task_step_image_ref(step)
	allowed_registry_prefixes := lib.rule_data("allowed_step_image_registry_prefixes")
	not image_ref_permitted(image_ref, allowed_registry_prefixes)
	result := lib.result_helper(rego.metadata.chain(), [step_index, tkn.task_name(task), image_ref])
}

# METADATA
# title: Permitted step image registry prefix list provided
# description: >-
#   Confirm the `allowed_step_image_registry_prefixes` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: step_image_registry_prefix_list_provided
#   failure_msg: Missing required allowed_step_image_registry_prefixes rule data
#   solution: >-
#     Make sure the xref:ec-cli:ROOT:configuration.adoc#_data_sources[data sources] contains a key
#     'allowed_step_image_registry_prefixes' that contains a list of approved registries
#     that can be used to run tasks in the build pipeline.
#
deny contains result if {
	count(lib.rule_data("allowed_step_image_registry_prefixes")) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

image_ref_permitted(image_ref, allowed_prefixes) if {
	some allowed_prefix in allowed_prefixes
	startswith(_normalize_image_ref(image_ref), allowed_prefix)
}

_normalize_image_ref(image_ref) := normalized if {
	parts := split(image_ref, "://")
	parts[0] == "oci"
	normalized := parts[1]
} else := normalized if {
	parts := split(image_ref, "://")
	count(parts) == 1
	normalized := image_ref
}
