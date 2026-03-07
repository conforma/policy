#
# METADATA
# title: rpm-ostree Task
# description: >-
#   This package is responsible for verifying the rpm-ostree Tekton Task was executed with the
#   expected parameters.
#
package rpm_ostree_task

import rego.v1

import data.lib
import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data
import data.lib.tekton

# METADATA
# title: Builder image parameter
# description: >-
#   Verify the BUILDER_IMAGE parameter of the rpm-ostree Task uses an image reference that is both
#   pinned to a digest and starts with a pre-defined list of prefixes. By default, the list of
#   prefixes is empty allowing any pinned image reference to be used. This is customizable via the
#   `allowed_rpm_ostree_builder_image_prefixes` rule data.
# custom:
#   short_name: builder_image_param
#   failure_msg: "%s"
#   solution: >-
#     Make sure the rpm-ostree Task uses a pinned image reference from a pre-approved location.
#   collections:
#   - redhat
#   effective_on: 2024-03-20T00:00:00Z
#
deny contains result if {
	some error in builder_image_param_errors
	result := _with_effective_on(metadata.result_helper(rego.metadata.chain(), [error.msg]), error)
}

# METADATA
# title: Rule data
# description: >-
#   Verify the rule data used by this package, `allowed_rpm_ostree_builder_image_prefixes`, is in
#   the expected format.
# custom:
#   short_name: rule_data
#   failure_msg: "%s"
#   solution: >-
#     Make sure the `allowed_rpm_ostree_builder_image_prefixes` rule data is in the expected format
#     in the data source.
#   collections:
#   - redhat
#
deny contains result if {
	some e in rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# Detect when an image reference is not pinned to a digest.
builder_image_param_errors contains error if {
	some image in _builder_images
	lib.image.parse(image).digest == ""
	error := {"msg": sprintf("BUILDER_IMAGE %q is not pinned to a digest", [image])}
}

# Detect when an image reference does not start with with any of the pre-approved prefixes.
builder_image_param_errors contains error if {
	some image in _builder_images

	# There are no matches
	count([prefix |
		some prefix in _allowed_prefixes
		startswith(image, prefix.value)
	]) == 0

	pretty_prefixes := concat(", ", [prefix.value | some prefix in _allowed_prefixes])

	error := {"msg": sprintf(
		"BUILDER_IMAGE %q does not start with a pre-approved prefix: %s",
		[image, pretty_prefixes],
	)}
}

# Detect when an image starts with a pre-approved prefix, but that prefix has expiration date.
builder_image_param_errors contains error if {
	some image in _builder_images

	# There is a match, but it has an expiration date.
	some prefix in _allowed_prefixes
	startswith(image, prefix.value)
	prefix.expires_on != ""

	error := {
		"msg": sprintf(
			"BUILDER_IMAGE %q starts with %q prefix that expires on %s",
			[image, prefix.value, prefix.expires_on],
		),
		"effective_on": prefix.expires_on,
	}
}

rule_data_errors contains error if {
	schema := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {"anyOf": [
			{
				"type": "object",
				"properties": {"value": {"type": "string"}, "expires_on": {"type": "string"}},
				"additionalProperties": false,
				"required": ["value"],
			},
			{"type": "string"},
		]},
		"uniqueItems": true,
	}

	some e in j.validate_schema(rule_data.rule_data(_rule_data_key), schema)

	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

# _builder_images is a set of image references. Each corresponding to the BUILDER_IMAGE parameter
# of an rpm-ostree Task.
_builder_images contains image if {
	some att in lib.pipelinerun_attestations
	some task in tekton.tasks(att)
	"rpm-ostree" in tekton.task_names(task)
	image := tekton.task_param(task, "BUILDER_IMAGE")
}

# _allowed_prefixes is a set of objects. Each object is guaranteed to contains a `value` attribute.
# If there are no items in the underlying rule data, this rules does not produce a result.
_allowed_prefixes := prefixes if {
	allowed_prefixes := rule_data.rule_data(_rule_data_key)
	count(allowed_prefixes) > 0
	prefixes := [_prefix_obj(prefix) | some prefix in allowed_prefixes]
}

# _prefix_obj ensures the given prefix value is wrapped in an object.
_prefix_obj(prefix) := prefix if {
	prefix.value
} else := {"value": prefix}

_with_effective_on(obj, record) := new_obj if {
	new_obj := object.union(obj, {"effective_on": record.effective_on})
} else := obj

_rule_data_key := "allowed_rpm_ostree_builder_image_prefixes"
