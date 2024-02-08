#
# METADATA
# description: >-
#   Check if the image has the expected labels set. The rules in this package
#   distinguish file-based catalog (FBC) images from all other images. When
#   checking an FBC image, a policy rule may use a different set of rule data.
#   An FBC image is detected by the presence of the
#   operators.operatorframework.io.index.configs.v1 label.
#
package policy.release.labels

import rego.v1

import data.lib

# METADATA
# title: Deprecated labels
# description: >-
#   Check the image for the presence of labels that have been deprecated.
#   Use the rule data key `deprecated_labels` to set the list of labels
#   to check.
# custom:
#   short_name: deprecated_labels
#   failure_msg: The %q label is deprecated, replace with %q
#   solution: >-
#     Update the image build process to not set the deprecated labels.
#   collections:
#   - redhat
#
deny contains result if {
	some label in labels
	some deprecated_label in lib.rule_data("deprecated_labels")
	label.name == deprecated_label.name
	result := lib.result_helper_with_term(
		rego.metadata.chain(),
		[label.name, deprecated_label.replacement],
		label.name,
	)
}

# METADATA
# title: Required labels
# description: >-
#   Check the image for the presence of labels that are required.
#   Use the rule data `required_labels` key to set the list of labels
#   to check, or the `fbc_required_labels` key for fbc images.
# custom:
#   short_name: required_labels
#   failure_msg: 'The required %q label is missing. Label description: %s'
#   solution: >-
#     Update the image build process to set the required labels.
#   collections:
#   - redhat
#
deny contains result if {
	found_labels := {name |
		some label in labels
		name := label.name
	}
	some required_label in required_labels
	name := required_label.name
	not name in found_labels
	description := required_label.description
	result := lib.result_helper_with_term(rego.metadata.chain(), [name, description], name)
}

# METADATA
# title: Optional labels
# description: >-
#   Check the image for the presence of labels that are recommended,
#   but not required. Use the rule data `optional_labels` key to set
#   the list of labels to check, or the `fbc_optional_labels` key for
#   fbc images.
# custom:
#   short_name: optional_labels
#   failure_msg: 'The optional %q label is missing. Label description: %s'
#   solution: >-
#     Update the image build process to set the optional labels.
#   collections:
#   - redhat
#
warn contains result if {
	found_labels := {name |
		some label in labels
		name := label.name
	}
	some optional_label in optional_labels
	name := optional_label.name
	not name in found_labels
	description := optional_label.description
	result := lib.result_helper_with_term(rego.metadata.chain(), [name, description], name)
}

# METADATA
# title: Disallowed inherited labels
# description: >-
#   Check that certain labels on the image have different values than the labels
#   from the parent image. If the label is inherited from the parent image but not
#   redefined for the image, it will contain an incorrect value for the image.
#   Use the rule data `disallowed_inherited_labels` key to set the list of labels
#   to check, or the `fbc_disallowed_inherited_labels` key for fbc images.
# custom:
#   short_name: disallowed_inherited_labels
#   failure_msg: The %q label should not be inherited from the parent image
#   solution: >-
#     Update the image build process to overwrite the inherited labels.
#   collections:
#   - redhat
#
deny contains result if {
	some inherited_label in disallowed_inherited_labels
	name := inherited_label.name
	_value(labels, name) == _value(parent_labels, name)
	result := _with_effective_on(
		lib.result_helper_with_term(rego.metadata.chain(), [name], name),
		inherited_label,
	)
}

# _with_effective_on annotates the result with the item's effective_on attribute. If the item does
# not have the attribute, result is returned unmodified.
# TODO: Move this to a shared location, or maybe create new result helper function.
_with_effective_on(result, item) := new_result if {
	# TODO: We may want to check if result already has effective_on set. And if so, compare it with
	# the item's effective_on. Use the lowest or highest value? Lowest means the data could activate
	# a policy rule that is not active. Unclear if that's intended - corner case? Highest probably
	# better represents the intent.
	new_result := json.patch(result, [{"op": "add", "path": "/effective_on", "value": item.effective_on}])
} else := result

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `required_labels`,	`fbc_required_labels`, `optional_labels`, `fbc_optional_labels`,
#   `disallowed_inherited_labels`, `fbc_disallowed_inherited_labels`, and `deprecated_labels`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [error])
}

labels contains label if {
	some name, value in input.image.config.Labels
	count(value) > 0
	label := {"name": name, "value": value}
}

parent_labels contains label if {
	some name, value in input.image.parent.config.Labels
	count(value) > 0
	label := {"name": name, "value": value}
}

_value(labels, name) := [v |
	some label in labels
	label.name == name
	v := label.value
][0]

required_labels := lib.rule_data("required_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_required_labels")

optional_labels := lib.rule_data("optional_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_optional_labels")

disallowed_inherited_labels := lib.rule_data("disallowed_inherited_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_disallowed_inherited_labels")

# A file-based catalog (FBC) image is just like a regular binary image, but
# with a very specific application in the operator framework ecosystem. Here
# we use heurisitics to determine whether or not the image is an FBC image.

default is_fbc := false

is_fbc if {
	some label in labels
	label.name == "operators.operatorframework.io.index.configs.v1"
}

_rule_data_errors contains msg if {
	name_only := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {
			"type": "object",
			"properties": {"name": {"type": "string"}, "effective_on": {"type": "string"}},
			"additionalProperties": false,
			"required": ["name"],
		},
		"uniqueItems": true,
	}

	name_and_description := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {
			"type": "object",
			"properties": {
				"name": {"type": "string"},
				"description": {"type": "string"},
				"effective_on": {"type": "string"},
			},
			"additionalProperties": false,
			"required": ["name", "description"],
		},
		"uniqueItems": true,
	}

	deprecated := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {
			"type": "object",
			"properties": {
				"name": {"type": "string"},
				"replacement": {"type": "string"},
				"effective_on": {"type": "string"},
			},
			"additionalProperties": false,
			"required": ["name", "replacement"],
		},
		"uniqueItems": true,
	}

	items := [
		["required_labels", name_and_description],
		["fbc_required_labels", name_and_description],
		["optional_labels", name_and_description],
		["fbc_optional_labels", name_and_description],
		["disallowed_inherited_labels", name_only],
		["optional_disallowed_inherited_labels", name_only],
		["fbc_disallowed_inherited_labels", name_only],
		["deprecated_labels", deprecated],
	]
	some item in items
	key := item[0]
	schema := item[1]

	# match_schema expects either a marshaled JSON resource (String) or an Object. It doesn't
	# handle an Array directly.
	value := json.marshal(lib.rule_data(key))
	some violation in json.match_schema(
		value,
		schema,
	)[1]
	msg := sprintf("Rule data %s has unexpected format: %s", [key, violation.error])
}
