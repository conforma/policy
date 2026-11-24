package stepaction_image_test

import rego.v1

import data.lib.assertions

import data.stepaction_image as image

test_image_accessible if {
	stepaction := {
		"kind": "StepAction",
		"spec": {"image": "registry.io/repository/ok:1"},
	}

	assertions.assert_empty(image.deny) with input as stepaction
		with ec.oci.image_manifest as mock_image_manifest
		with data.rule_data as default_rule_data
}

test_image_not_accessible if {
	stepaction := {
		"kind": "StepAction",
		"spec": {"image": "registry.io/repository/not_ok:1"},
	}

	expected := {{
		"code": "stepaction_image.accessible",
		"msg": `Image ref "registry.io/repository/not_ok:1" is inaccessible`,
		"term": "registry.io/repository/not_ok:1",
	}}

	assertions.assert_equal_results(expected, image.deny) with input as stepaction
		with ec.oci.image_manifest as mock_image_manifest
		with data.rule_data as default_rule_data
}

test_image_not_permitted if {
	stepaction := {
		"kind": "StepAction",
		"spec": {"image": "registry.io/repository/ok:1"},
	}

	rule_data := {"allowed_step_image_registry_prefixes": ["dope.registry.io/"]}

	expected := {{
		"code": "stepaction_image.permitted",
		"msg": `Image ref "registry.io/repository/ok:1" is disallowed`,
		"term": "noname/noversion",
	}}

	assertions.assert_equal_results(expected, image.deny) with input as stepaction
		with ec.oci.image_manifest as mock_image_manifest
		with data.rule_data as rule_data
}

test_rule_data_list_empty if {
	expected := {
		{
			"code": "stepaction_image.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(expected, image.deny) with data.rule_data as {}
}

test_rule_data_list_format if {
	d := {"allowed_step_image_registry_prefixes": [
		# Wrong type
		1,
		# Duplicated items
		"registry.local/",
		"registry.local/",
	]}

	expected := {
		{
			"code": "stepaction_image.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(expected, image.deny) with data.rule_data as d
}

# A present but scalar `allowed_step_image_registry_prefixes` value must produce a
# format rejection from the v2 rule instead of silently skipping the check. The
# legacy rule_data is untouched: a builtin error in its schema validation still
# suppresses its result, which is the gap the v2 rule closes. The permitted
# consumer is independently fail-closed under scalar data (it denies any image),
# so the isolated assertion below uses a StepAction without an image to show that
# only the v2 rule fires; the assertion with a real image locks in that existing
# consumer behavior.
test_rule_data_v2_scalar_rejected if {
	stepaction_without_image := {"kind": "StepAction", "spec": {}}

	expected_int := {{
		"code": "stepaction_image.rule_data_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(image.deny, expected_int) with input as stepaction_without_image
		with data.rule_data as {"allowed_step_image_registry_prefixes": 1}

	expected_str := {{
		"code": "stepaction_image.rule_data_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(image.deny, expected_str) with input as stepaction_without_image
		with data.rule_data as {"allowed_step_image_registry_prefixes": "x"}

	expected_bool := {{
		"code": "stepaction_image.rule_data_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: boolean",
		"severity": "failure",
	}}
	assertions.assert_equal_results(image.deny, expected_bool) with input as stepaction_without_image
		with data.rule_data as {"allowed_step_image_registry_prefixes": true}

	stepaction_with_image := {
		"kind": "StepAction",
		"spec": {"image": "registry.io/repository/ok:1"},
	}

	expected_with_image := expected_int | {{
		"code": "stepaction_image.permitted",
		"msg": `Image ref "registry.io/repository/ok:1" is disallowed`,
		"term": "noname/noversion",
	}}
	assertions.assert_equal_results(image.deny, expected_with_image) with input as stepaction_with_image
		with ec.oci.image_manifest as mock_image_manifest
		with data.rule_data as {"allowed_step_image_registry_prefixes": 1}
}

# A string value is malformed even when it contains JSON text for a valid array:
# the legacy rule parses the JSON text and reports the empty-array violation,
# while the v2 rule rejects the string itself. A native empty array stays invalid
# for this key on both rules.
test_rule_data_v2_json_text_string_rejected if {
	expected_json_text := {
		{
			"code": "stepaction_image.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(image.deny, expected_json_text) with data.rule_data as {"allowed_step_image_registry_prefixes": "[]"}

	expected_native_empty := {
		{
			"code": "stepaction_image.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(image.deny, expected_native_empty) with data.rule_data as {"allowed_step_image_registry_prefixes": []}
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_rule_data_v2_precedence if {
	expected := {{
		"code": "stepaction_image.rule_data_v2",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}

	assertions.assert_equal_results(image.deny, expected) with data.rule_data_custom as {"allowed_step_image_registry_prefixes": 1}
		with data.rule_data as {"allowed_step_image_registry_prefixes": ["registry.io/"]}
}

# Shape controls locking in the current behavior of both format rules for a null
# value and a wrong-container value.
test_rule_data_v2_shape_controls if {
	expected_null := {
		{
			"code": "stepaction_image.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(image.deny, expected_null) with data.rule_data as {"allowed_step_image_registry_prefixes": null}

	expected_object := {
		{
			"code": "stepaction_image.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
		{
			"code": "stepaction_image.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(image.deny, expected_object) with data.rule_data as {"allowed_step_image_registry_prefixes": {"registry.local/": true}}
}

mock_image_manifest(ref) := {} if {
	startswith(ref, "registry.io/repository/ok")
}

default_rule_data := {"allowed_step_image_registry_prefixes": ["registry.io/"]}
