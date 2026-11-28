package stepaction_image_test

import rego.v1

import data.lib.assertions

import data.stepaction_image as image

test_image_accessible if {
	stepaction := {
		"kind": "StepAction",
		"spec": {"image": "registry.io/repository/ok:1"},
	}

	assertions.assert_empty(_legacy_denies) with input as stepaction
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

	assertions.assert_equal_results(expected, _legacy_denies) with input as stepaction
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

	assertions.assert_equal_results(expected, _legacy_denies) with input as stepaction
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

	assertions.assert_equal_results(expected, _legacy_denies) with data.rule_data as {}
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

	assertions.assert_equal_results(expected, _legacy_denies) with data.rule_data as d
}

mock_image_manifest(ref) := {} if {
	startswith(ref, "registry.io/repository/ok")
}

default_rule_data := {"allowed_step_image_registry_prefixes": ["registry.io/"]}

# Preserve the legacy contract during the v2 migration window.
_legacy_denies contains result if {
	some result in image.deny
	not endswith(result.code, "_v2")
}

# G18 / RA05-STEPACTION-IMAGE-MISSING-001: spec remains selected.
test_stepaction_image_missing_v2 if {
	stepaction := {"kind": "StepAction", "spec": {"image": "registry.io/repository/ok:1"}}
	assertions.assert_empty(image.deny) with input as stepaction
		with ec.oci.image_manifest as mock_image_manifest with data.rule_data as default_rule_data
	missing := json.remove(stepaction, ["spec/image"])
	results := image.deny with input as missing
		with ec.oci.image_manifest as mock_image_manifest with data.rule_data as default_rule_data
	assertions.assert_equal({r.code | some r in results}, {"stepaction_image.accessible_v2", "stepaction_image.permitted_v2"})
	every result in results {
		result.term == "noname/noversion"
		result.effective_on == "2027-01-11T00:00:00Z"
	}
}

test_stepaction_image_wrong_type_v2 if {
	every value in [null, 1, true, {}, [], "", " "] {
		results := image.deny with input as {"kind": "StepAction", "spec": {"image": value}}
			with ec.oci.image_manifest as mock_image_manifest with data.rule_data as default_rule_data
		codes := {r.code | some r in results}
		"stepaction_image.accessible_v2" in codes
		"stepaction_image.permitted_v2" in codes
	}
}

test_stepaction_image_adverse_controls_v2 if {
	results := image.deny with input as {"kind": "StepAction", "spec": {"image": "registry.io/repository/not_ok:1"}}
		with ec.oci.image_manifest as mock_image_manifest with data.rule_data as default_rule_data
	assertions.assert_equal({r.code | some r in results}, {"stepaction_image.accessible", "stepaction_image.accessible_v2"})
	disallowed := image.deny with input as {"kind": "StepAction", "spec": {"image": "registry.io/repository/ok:1"}}
		with ec.oci.image_manifest as mock_image_manifest
		with data.rule_data.allowed_step_image_registry_prefixes as ["other.registry/"]
	assertions.assert_equal({r.code | some r in disallowed}, {"stepaction_image.permitted", "stepaction_image.permitted_v2"})
}
