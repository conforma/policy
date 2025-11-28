package stepaction_image_test

import rego.v1

import data.lib
import data.stepaction_image as image

test_image_accessible if {
	stepaction := {
		"kind": "StepAction",
		"spec": {"image": "registry.io/repository/ok:1"},
	}

	lib.assert_empty(image.deny) with input as stepaction
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

	lib.assert_equal_results(expected, image.deny) with input as stepaction
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

	lib.assert_equal_results(expected, image.deny) with input as stepaction
		with ec.oci.image_manifest as mock_image_manifest
		with data.rule_data as rule_data
}

test_rule_data_list_empty if {
	expected := {{
		"code": "stepaction_image.rule_data",
		# regal ignore:line-length
		"msg": "Rule data allowed_step_image_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
		"severity": "failure",
	}}

	lib.assert_equal_results(expected, image.deny) with data.rule_data as {}
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
	}

	lib.assert_equal_results(expected, image.deny) with data.rule_data as d
}

mock_image_manifest(ref) := {} if {
	startswith(ref, "registry.io/repository/ok")
}

default_rule_data := {"allowed_step_image_registry_prefixes": ["registry.io/"]}
