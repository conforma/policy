#
# METADATA
# title: Tekton Task Step image registry policies
# description: >-
#   This package ensures that a Task definition contains expected values for the image references
#   used by the Task's steps.
#
package step_image_registries

import rego.v1

import data.lib.metadata
import data.lib.rule_data
import data.lib.tkn_bundle

import data.lib.json as j
import data.lib.k8s

# METADATA
# title: Step images come from permitted registry
# description: >-
#   Confirm that each step in the Task uses a container image with a URL that matches one of the
#   prefixes in the provided list of allowed step image registry prefixes. The list is customizeable
#   via the `allowed_step_image_registry_prefixes` rule data key.
# custom:
#   short_name: step_images_permitted
#   failure_msg: Step %d uses disallowed image ref '%s'
#   solution: >-
#     Make sure the container image used in each step of the Task comes from an approved registry.
#
deny contains result if {
	some task in tkn_bundle.tasks
	task.kind == "Task"

	some step_index, step in task.spec.steps
	image_ref := step.image
	allowed_registry_prefixes := rule_data.get(_rule_data_key)
	not image_ref_permitted(image_ref, allowed_registry_prefixes)

	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[step_index, image_ref],
		k8s.name_version(task),
	)
}

# METADATA
# title: Permitted step image registry prefix list provided
# description: >-
#   Confirm the `allowed_step_image_registry_prefixes` rule data was provided, since it's
#   required by the policy rules in this package.
# custom:
#   short_name: step_image_registry_prefix_list_provided
#   failure_msg: "%s"
#   solution: >-
#     Make sure the xref:cli:ROOT:configuration.adoc#_data_sources[data sources] contains a key
#     'allowed_step_image_registry_prefixes' that contains a list of approved registries
#     that can be used to run tasks in the build pipeline.
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

image_ref_permitted(image_ref, allowed_prefixes) if {
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
}

_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get(_rule_data_key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_key := "allowed_step_image_registry_prefixes"
