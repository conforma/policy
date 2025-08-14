#
# METADATA
# title: Labels
# description: >-
#   Check if the image has the expected labels set. The rules in this package
#   distinguish file-based catalog (FBC) images from all other images. When
#   checking an FBC image, a policy rule may use a different set of rule data.
#   An FBC image is detected by the presence of the
#   operators.operatorframework.io.index.configs.v1 label.
#
package labels

import rego.v1

import data.lib
import data.lib.image
import data.lib.json as j

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
	found_labels := {label.name | some label in _image_labels}
	some optional_label in optional_labels
	name := optional_label.name
	not name in found_labels
	description := optional_label.description
	result := _with_effective_on(
		lib.result_helper_with_term(rego.metadata.chain(), [name, description], name),
		optional_label,
	)
}

# METADATA
# title: Inaccessible image manifest
# description: >-
#   The image manifest is not accessible.
# custom:
#   short_name: inaccessible_manifest
#   failure_msg: Manifest of the image %q is inaccessible
#   solution: >-
#     Check the provided authentication configuration and the credentials
#     within it.
#   collections:
#   - redhat
#
deny contains result if {
	manifest := ec.oci.image_manifest(input.image.ref)
	is_null(manifest)
	result := lib.result_helper(rego.metadata.chain(), [input.image.ref])
}

# METADATA
# title: Inaccessible image config
# description: >-
#   The image config is not accessible.
# custom:
#   short_name: inaccessible_config
#   failure_msg: Image config of the image %q is inaccessible
#   solution: >-
#     Check the provided authentication configuration and the credentials
#     within it.
#   collections:
#   - redhat
#
deny contains result if {
	manifest := ec.oci.image_manifest(input.image.ref)
	digest := object.get(manifest, ["config", "digest"], "")
	ref := image.parse(input.image.ref)
	config := ec.oci.blob(sprintf("%s@%s", [ref.repo, digest]))
	is_null(config)
	result := lib.result_helper(rego.metadata.chain(), [input.image.ref])
}

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
	some label in _image_labels
	some deprecated_label in lib.rule_data("deprecated_labels")
	label.name == deprecated_label.name
	result := _with_effective_on(
		lib.result_helper_with_term(
			rego.metadata.chain(),
			[label.name, deprecated_label.replacement],
			label.name,
		),
		deprecated_label,
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
#   failure_msg: '%s'
#   solution: >-
#     Update the image build process to set the required labels.
#   collections:
#   - redhat
#
deny contains result if {
	is_set(_image_labels)

	some err in _required_labels_errors
	result := object.union(lib.result_helper(rego.metadata.chain(), []), err)
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
	_value(_image_labels, name) == _value(_parent_labels, name)
	result := _with_effective_on(
		lib.result_helper_with_term(rego.metadata.chain(), [name], name),
		inherited_label,
	)
}

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
	some e in _rule_data_errors
	result := lib.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# METADATA
# title: Inaccessible parent image manifest
# description: >-
#   The parent image manifest is not accessible.
# custom:
#   short_name: inaccessible_parent_manifest
#   failure_msg: Manifest of the image %q, parent of image %q is inaccessible
#   solution: >-
#     Check the provided authentication configuration and the credentials
#     within it.
#   collections:
#   - redhat
#
deny contains result if {
	_has_parent
	is_null(_parent.manifest)
	result := lib.result_helper(rego.metadata.chain(), [_parent.ref, input.image.ref])
}

# METADATA
# title: Inaccessible parent image config
# description: >-
#   The parent image config is not accessible.
# custom:
#   short_name: inaccessible_parent_config
#   failure_msg: Image config of the image %q, parent of image %q is inaccessible
#   solution: >-
#     Check the provided authentication configuration and the credentials
#     within it.
#   collections:
#   - redhat
#
deny contains result if {
	_has_parent
	parent_ref := image.parse(_parent.ref)
	is_null(_config(parent_ref.repo, _parent.manifest))
	result := lib.result_helper(rego.metadata.chain(), [_parent.ref, input.image.ref])
}

_config(repository, manifest) := config if {
	config_ref := sprintf("%s@%s", [repository, manifest.config.digest])

	config = json.unmarshal(ec.oci.blob(config_ref))
} else := null

_image_labels := labels if {
	manifest := ec.oci.image_manifest(input.image.ref)

	ref := image.parse(input.image.ref)

	config := _config(ref.repo, manifest)
	not is_null(config)

	labels := {label |
		some name, value in object.get(config, ["config", "Labels"], [])
		label = {"name": name, "value": value}
	}
}

_has_parent if {
	image_manifest := ec.oci.image_manifest(input.image.ref)

	raw_name := image_manifest.annotations["org.opencontainers.image.base.name"]
	raw_name != ""

	digest := image_manifest.annotations["org.opencontainers.image.base.digest"]
	digest != ""
}

_parent := {"ref": ref, "manifest": manifest, "config": config} if {
	image_manifest := ec.oci.image_manifest(input.image.ref)

	raw_name := image_manifest.annotations["org.opencontainers.image.base.name"]
	raw_name != ""

	digest := image_manifest.annotations["org.opencontainers.image.base.digest"]
	digest != ""

	# Sometimes the name annotation is a ref including a digest, likely the
	# digest of the image index. Make sure that digest gets removed.
	name := _strip_digest(raw_name)

	ref = sprintf("%s@%s", [name, digest])

	manifest = ec.oci.image_manifest(ref)

	config = _config(name, manifest)
}

_parent_labels contains label if {
	labels := object.get(_parent.config, ["config", "Labels"], [])

	some name, value in labels
	label := {"name": name, "value": value}
}

_value(labels, name) := [label.value |
	some label in labels
	label.name == name
][0]

_strip_digest(ref_with_digest_maybe) := regex.replace(ref_with_digest_maybe, `@[^@]+$`, "")

required_labels := lib.rule_data("required_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_required_labels")

optional_labels := lib.rule_data("optional_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_optional_labels")

disallowed_inherited_labels := lib.rule_data("disallowed_inherited_labels") if {
	not is_fbc
} else := lib.rule_data("fbc_disallowed_inherited_labels")

# _with_effective_on annotates the result with the item's effective_on attribute. If the item does
# not have the attribute, result is returned unmodified.
_with_effective_on(result, item) := new_result if {
	new_result := object.union(result, {"effective_on": item.effective_on})
} else := result

# A file-based catalog (FBC) image is just like a regular binary image, but
# with a very specific application in the operator framework ecosystem. Here
# we use heurisitics to determine whether or not the image is an FBC image.

default is_fbc := false

is_fbc if {
	some label in _image_labels
	label.name == "operators.operatorframework.io.index.configs.v1"
}

_required_labels_errors contains err if {
	label_names := {label.name | some label in _image_labels}
	some required_label in required_labels
	name := required_label.name
	not name in label_names
	description := required_label.description
	err := _with_effective_on(
		{
			"msg": sprintf("The required %q label is missing. Label description: %s", [name, description]),
			"term": name,
		},
		required_label,
	)
}

_required_labels_errors contains err if {
	some label in _image_labels
	some required_label in required_labels
	label.name == required_label.name
	name := label.name
	value := label.value

	allowed_values := {v | some v in required_label.values}
	count(allowed_values) > 0
	not value in allowed_values

	err := _with_effective_on(
		{
			"msg": sprintf(
				"The %q label has an unexpected %q value. Must be one of: %s",
				[name, value, concat(", ", allowed_values)],
			),
			"term": name,
		},
		required_label,
	)
}

_rule_data_errors contains error if {
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

	name_description_and_values := {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"items": {
			"type": "object",
			"properties": {
				"name": {"type": "string"},
				"description": {"type": "string"},
				"effective_on": {"type": "string"},
				"values": {
					"type": "array",
					"items": {"type": "string"},
				},
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
		["required_labels", name_description_and_values],
		["fbc_required_labels", name_description_and_values],
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

	some e in j.validate_schema(
		lib.rule_data(key),
		schema,
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}
