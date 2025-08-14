package labels_test

import rego.v1

import data.labels
import data.lib

# For these tests builtin functions ec.oci.image_manifest and ec.oci.blob need
# to be mocked. Both take a single parameter -- the image reference, for which
# they return the manifest JSON or the bytes of the blob. In order to have the
# mock implementations: _mock_image_manifest and _mock_blob return the data the
# test requires the image reference is constructed such that it contains a
# serialized array of JSON patches following the # sign in the image reference,
# e.g.: registry.io/repository/image@sha256:digest#[{"op": ...}].
# There are several helper functions to allow for readability and somewhat for
# maintainability of the tests:
#  * _test_ref_with_labels(labels)
#  * _test_ref_with_labels_and_parent_labels(labels, parent_labels)
# The mock functions also support returning null value if the image reference
# starts with "fail" or contains "#fail".

test_all_good if {
	lib.assert_empty(labels.deny | labels.warn) with input.image.ref as _test_ref_with_labels({
		"name": "test-image",
		"description": "test image",
		"summary": "test",
		"vendor": "Acme, Inc.",
	})
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	lib.assert_empty(labels.deny | labels.warn) with input.image.ref as _test_ref_with_labels({
		"fbc.name": "test-image",
		"fbc.description": "test image",
		"fbc.summary": "test",
		"fbc.vendor": "Acme, Inc.",
		"operators.operatorframework.io.index.configs.v1": "/config",
	})
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data
}

test_deprecated_image_labels if {
	expected := {{
		"code": "labels.deprecated_labels",
		"msg": "The \"oldie\" label is deprecated, replace with \"shiny\"",
		"term": "oldie",
	}}

	ref := _test_ref_with_labels({
		"name": "test-image",
		"description": "test image",
		"summary": "test",
		"oldie": "sudo rm -rf /",
		"vendor": "Acme, Inc.",
	})

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date
}

test_required_image_labels if {
	expected := {{
		"code": "labels.required_labels",
		"msg": "The required \"name\" label is missing. Label description: Name of the image.",
		"term": "name",
	}}

	ref := _test_ref_with_labels({
		"description": "test image",
		"summary": "test",
		"vendor": "Acme, Inc.",
	})

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date
}

test_fbc_required_image_labels if {
	expected := {{
		"code": "labels.required_labels",
		"msg": "The required \"fbc.name\" label is missing. Label description: Name of the FBC image.",
		"term": "fbc.name",
	}}

	ref := _test_ref_with_labels({
		"fbc.description": "test image",
		"fbc.summary": "test",
		"fbc.vendor": "Acme, Inc.",
		"operators.operatorframework.io.index.configs.v1": "/config",
	})

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date
}

test_required_image_labels_with_values if {
	expected := {{
		"code": "labels.required_labels",
		"msg": "The \"vendor\" label has an unexpected \"DeVille, Inc.\" value. Must be one of: Acme, Inc., Goodfellas, Inc.",
		"term": "vendor",
	}}

	ref := _test_ref_with_labels({
		"name": "test-image",
		"description": "test image",
		"summary": "test",
		"vendor": "DeVille, Inc.",
	})

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date
}

test_fbc_required_image_labels_with_values if {
	expected := {{
		"code": "labels.required_labels",
		# regal ignore:line-length
		"msg": "The \"fbc.vendor\" label has an unexpected \"DeVille, Inc.\" value. Must be one of: Acme, Inc., Goodfellas, Inc.",
		"term": "fbc.vendor",
	}}

	ref := _test_ref_with_labels({
		"fbc.name": "test-image",
		"fbc.description": "test image",
		"fbc.summary": "test",
		"fbc.vendor": "DeVille, Inc.",
		"operators.operatorframework.io.index.configs.v1": "/config",
	})

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date
}

test_optional_image_labels if {
	expected := {{
		"code": "labels.optional_labels",
		"msg": "The optional \"summary\" label is missing. Label description: A short description of the image.",
		"term": "summary",
	}}

	ref := _test_ref_with_labels({
		"name": "test-image",
		"description": "test image",
		"vendor": "Acme, Inc.",
	})

	lib.assert_equal_results(labels.warn, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.warn) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date
}

test_fbc_optional_image_labels if {
	expected := {{
		"code": "labels.optional_labels",
		"msg": "The optional \"fbc.summary\" label is missing. Label description: A short description of the FBC image.",
		"term": "fbc.summary",
	}}

	ref := _test_ref_with_labels({
		"fbc.name": "test-image",
		"fbc.description": "test image",
		"fbc.vendor": "Acme, Inc.",
		"operators.operatorframework.io.index.configs.v1": "/config",
	})

	lib.assert_equal_results(labels.warn, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.warn) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date
}

test_disallowed_inherited_image_labels if {
	expected := {{
		"code": "labels.disallowed_inherited_labels",
		"msg": "The \"unique\" label should not be inherited from the parent image",
		"term": "unique",
	}}

	ref := _test_ref_with_labels_and_parent_labels(
		{
			"name": "test-image",
			"description": "test image",
			"summary": "test",
			"unique": "spam",
			"vendor": "Acme, Inc.",
		},
		{
			"name": "parent-image",
			"description": "parent image",
			"summary": "parent",
			"unique": "spam",
			"vendor": "Acme, Inc.",
		},
	)

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date

	# A missing label on either image does not trigger a violation.
	lib.assert_empty(labels.deny) with input.image.ref as _test_ref_with_labels_and_parent_labels(
		{
			"name": "test-image",
			"description": "test image",
			"summary": "test",
			"vendor": "Acme, Inc.",
		},
		{
			"name": "parent-image",
			"description": "parent image",
			"summary": "parent",
			"unique": "spam",
			"vendor": "Acme, Inc.",
		},
	)
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	lib.assert_empty(labels.deny) with input.image.ref as _test_ref_with_labels_and_parent_labels(
		{
			"name": "test-image",
			"description": "test image",
			"summary": "test",
			"unique": "spam",
			"vendor": "Acme, Inc.",
		},
		{
			"name": "parent-image",
			"description": "parent image",
			"summary": "parent",
			"vendor": "Acme, Inc.",
		},
	)
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data
}

test_fbc_disallowed_inherited_image_labels if {
	expected := {{
		"code": "labels.disallowed_inherited_labels",
		"msg": "The \"fbc.unique\" label should not be inherited from the parent image",
		"term": "fbc.unique",
	}}

	ref := _test_ref_with_labels_and_parent_labels(
		{
			"fbc.name": "test-image",
			"fbc.description": "test image",
			"fbc.summary": "test",
			"operators.operatorframework.io.index.configs.v1": "/config",
			"fbc.unique": "spam",
			"fbc.vendor": "Acme, Inc.",
		},
		{
			"fbc.name": "test-parent-image",
			"fbc.description": "test parent image",
			"fbc.summary": "parent",
			"fbc.unique": "spam",
			"fbc.vendor": "Acme, Inc.",
		},
	)

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	_assert_effective_on_date(labels.deny) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data_with_date

	# A missing label on either image does not trigger a violation.
	lib.assert_empty(labels.deny) with input.image.ref as _test_ref_with_labels_and_parent_labels(
		{
			"fbc.name": "test-image",
			"fbc.description": "test image",
			"fbc.summary": "test",
			"operators.operatorframework.io.index.configs.v1": "/config",
			"fbc.vendor": "Acme, Inc.",
		},
		{
			"fbc.name": "test-parent-image",
			"fbc.description": "test parent image",
			"fbc.summary": "parent",
			"fbc.unique": "spam",
			"fbc.vendor": "Acme, Inc.",
		},
	)
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data

	lib.assert_empty(labels.deny) with input.image.ref as _test_ref_with_labels_and_parent_labels(
		{
			"fbc.name": "test-image",
			"fbc.description": "test image",
			"fbc.summary": "test",
			"operators.operatorframework.io.index.configs.v1": "/config",
			"fbc.unique": "spam",
			"fbc.vendor": "Acme, Inc.",
		},
		{
			"fbc.name": "test-parent-image",
			"fbc.description": "test parent image",
			"fbc.summary": "parent",
			"fbc.vendor": "Acme, Inc.",
		},
	)
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data
}

test_image_manifest_inaccessible if {
	expected := {{
		"code": "labels.inaccessible_manifest",
		"msg": `Manifest of the image "fail@" is inaccessible`,
	}}

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as "fail@"
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data
}

test_image_config_inaccessible if {
	ref := _test_ref_patches([{
		"op": "add",
		"path": "/config/digest",
		"value": "#fail",
	}])

	expected := {{
		"code": "labels.inaccessible_config",
		"msg": sprintf(`Image config of the image %q is inaccessible`, [ref]),
	}}

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data
}

test_parent_image_manifest_inaccessible if {
	ref := _test_ref_patches(array.concat(
		_add_annotations({
			"org.opencontainers.image.base.name": "fail",
			"org.opencontainers.image.base.digest": "fake_digest",
		}),
		[_config(_add_labels({
			"name": "test-image",
			"description": "test image",
			"summary": "test",
			"vendor": "Acme, Inc.",
		}))],
	))

	expected := {{
		"code": "labels.inaccessible_parent_manifest",
		"msg": sprintf(`Manifest of the image "fail@fake_digest", parent of image %q is inaccessible`, [ref]),
	}}

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data
}

test_parent_image_config_inaccessible if {
	parent_digest := _test_digest([{
		"op": "add",
		"path": "/config/digest",
		"value": "#fail",
	}])
	parent_ref := sprintf("registry.io/repository/image@%s", [parent_digest])
	ref := _test_ref_patches(array.concat(
		_add_annotations({
			"org.opencontainers.image.base.name": "registry.io/repository/image",
			"org.opencontainers.image.base.digest": parent_digest,
		}),
		[_config(_add_labels({
			"name": "test-image",
			"description": "test image",
			"summary": "test",
			"vendor": "Acme, Inc.",
		}))],
	))

	expected := {{
		"code": "labels.inaccessible_parent_config",
		"msg": sprintf(`Image config of the image %q, parent of image %q is inaccessible`, [parent_ref, ref]),
	}}

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as ref
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as _rule_data
}

test_rule_data_provided if {
	d := {
		"required_labels": [
			# Wrong type
			1,
			# Duplicated items
			{"name": "name", "description": "label-description"},
			{"name": "name", "description": "label-description"},
			# Additional properties
			{"name": "name", "description": "label-description", "foo": "bar"},
			# Bad type for values
			{"name": "vendor", "description": "label-description", "values": [1]},
		],
		"fbc_required_labels": [1],
		"optional_labels": [1],
		"fbc_optional_labels": [1],
		"disallowed_inherited_labels": [
			# Wrong type
			1,
			# Duplicated items
			{"name": "name"},
			{"name": "name"},
			# Additional properties
			{"name": "name", "foo": "bar"},
		],
		"fbc_disallowed_inherited_labels": [1],
		"deprecated_labels": [
			# Wrong type
			1,
			# Duplicated items
			{"name": "deprecated-name", "replacement": "label-replacement"},
			{"name": "deprecated-name", "replacement": "label-replacement"},
			# Additional properties
			{"name": "deprecated-name", "replacement": "label-description", "foo": "bar"},
		],
	}

	expected := {
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data deprecated_labels has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data deprecated_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data deprecated_labels has unexpected format: 3: Additional property foo is not allowed",
			"severity": "warning",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data disallowed_inherited_labels has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_inherited_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data disallowed_inherited_labels has unexpected format: 3: Additional property foo is not allowed",
			"severity": "warning",
		},
		{
			"code": "labels.rule_data_provided",
			# regal ignore:line-length
			"msg": "Rule data fbc_disallowed_inherited_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data fbc_optional_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data fbc_required_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data optional_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data required_labels has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data required_labels has unexpected format: 0: Invalid type. Expected: object, given: integer",
			"severity": "failure",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data required_labels has unexpected format: 3: Additional property foo is not allowed",
			"severity": "warning",
		},
		{
			"code": "labels.rule_data_provided",
			"msg": "Rule data required_labels has unexpected format: 4.values.0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(labels.deny, expected) with input.image.ref as _test_ref_with_labels({
		"name": "test-image",
		"description": "test image",
		"summary": "test",
		"vendor": "Acme, Inc.",
	})
		with ec.oci.image_manifest as _mock_image_manifest
		with ec.oci.blob as _mock_blob
		with data.rule_data as d
}

test_strip_digest if {
	lib.assert_equal("foo", labels._strip_digest("foo"))
	lib.assert_equal("foo", labels._strip_digest("foo@bar"))
	lib.assert_equal("foo:latest", labels._strip_digest("foo:latest@bar"))
	lib.assert_equal("registry.io/registry/image", labels._strip_digest("registry.io/registry/image@sha256:ace0fba5e"))
}

_default_manifest := {
	"schemaVersion": 2,
	"mediaType": "application/vnd.oci.image.manifest.v1+json",
	"config": {
		"mediaType": "application/vnd.oci.image.config.v1+json",
		"size": 8172,
	},
	"annotations": {},
}

_default_config := {"config": {"Labels": {}}}

_p(ref) := json.unmarshal(regex.replace(ref, `^[^#]*#`, ""))

_mock_image_manifest(ref) := manifest if {
	not startswith(ref, "fail")
	manifest = json.patch(_default_manifest, _p(ref))
}

_mock_image_manifest(ref) := null if {
	startswith(ref, "fail")
}

_mock_blob(ref) := blob if {
	not contains(ref, "#fail")
	blob = json.marshal(json.patch(_default_config, _p(ref)))
}

_mock_blob(ref) := null if {
	contains(ref, "#fail")
}

_test_ref_with_labels(labels) := _test_ref_patches([_config(_add_labels(labels))])

_test_ref_with_labels_and_parent_labels(labels, parent_labels) := _test_ref_patches(array.concat(
	_add_annotations({
		"org.opencontainers.image.base.name": "registry.io/repository/parent_image",
		"org.opencontainers.image.base.digest": _test_digest([_config(_add_labels(parent_labels))]),
	}),
	[_config(_add_labels(labels))],
))

_test_ref_patches(patches) := sprintf("%s@%s", [
	"registry.io/repository/image",
	_test_digest(patches),
])

_test_digest(patches) := sprintf("sha256:image_digest#%s", [json.marshal(patches)])

_config(patches) := {
	"op": "add",
	"path": "/config/digest",
	"value": sprintf("sha256:image_config#%s", [json.marshal(patches)]),
}

_add_labels(labels) := [p | some k, v in labels; p = {
	"op": "add",
	"path": sprintf("/config/Labels/%s", [k]),
	"value": v,
}]

_add_annotations(annotations) := [p | some k, v in annotations; p = {
	"op": "add",
	"path": sprintf("/annotations/%s", [k]),
	"value": v,
}]

_rule_data := {
	"deprecated_labels": [{"name": "oldie", "replacement": "shiny"}],
	"required_labels": [
		{"name": "name", "description": "Name of the image."},
		{"name": "description", "description": "Detailed description of the image."},
		{"name": "vendor", "description": "Image provider", "values": ["Acme, Inc.", "Goodfellas, Inc."]},
	],
	"fbc_required_labels": [
		{"name": "fbc.name", "description": "Name of the FBC image."},
		{"name": "fbc.description", "description": "Detailed description of the FBC image."},
		{"name": "fbc.vendor", "description": "Image provider", "values": ["Acme, Inc.", "Goodfellas, Inc."]},
	],
	"optional_labels": [{"name": "summary", "description": "A short description of the image."}],
	"fbc_optional_labels": [{"name": "fbc.summary", "description": "A short description of the FBC image."}],
	"disallowed_inherited_labels": [{"name": "unique"}],
	"fbc_disallowed_inherited_labels": [{"name": "fbc.unique"}],
}

_mock_effective_on := "3000-01-01T00:00:00Z"

_rule_data_with_date[category] := values_with_date if {
	some category, values in _rule_data
	values_with_date := [value_with_date |
		some value in values
		value_with_date := object.union(value, {"effective_on": _mock_effective_on})
	]
}

_assert_effective_on_date(violations) if {
	got_effective_on := {date |
		some violation in violations
		date := object.get(violation, "effective_on", "")
	}
	lib.assert_equal(got_effective_on, {_mock_effective_on})
}
