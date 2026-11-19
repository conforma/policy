package rpm_ostree_task_test

import rego.v1

import data.lib
import data.lib.assertions
import data.lib.tekton_test
import data.rpm_ostree_task

test_success if {
	slsa_v02_attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{
				"name": "rpm-ostree-p",
				"ref": {"kind": "Task", "name": "rpm-ostree"},
				# regal ignore:line-length
				"invocation": {"parameters": {"BUILDER_IMAGE": "registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"}},
			}]},
		},
	}}

	# SLSA v1.0
	_base_task := tekton_test.slsav1_task("rpm-ostree")
	slsa_v1_task = tekton_test.with_results(
		_base_task,
		[{
			"name": "BUILDER_IMAGE",
			"value": "registry.local/builder:v1.0@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd",
		}],
	)

	slsa_v1_attestation := tekton_test.slsav1_attestation([slsa_v1_task])

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	assertions.assert_empty(rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data.allowed_rpm_ostree_builder_image_prefixes as ["registry.local/builder"]
}

test_builder_image_param_failures if {
	slsa_v02_attestation := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [
				{
					"name": "rpm-ostree-1",
					"ref": {"kind": "Task", "name": "rpm-ostree"},
					"invocation": {"parameters": {"BUILDER_IMAGE": "registry.local/spam:v0.2"}},
				},
				{
					"name": "rpm-ostree-2",
					"ref": {"kind": "Task", "name": "rpm-ostree"},
					# regal ignore:line-length
					"invocation": {"parameters": {"BUILDER_IMAGE": "registry.local/deprecated:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"}},
				},
			]},
		},
	}}

	# SLSA v1.0
	_slsa_v1_task_1_base := tekton_test.slsav1_task("rpm-ostree-1")
	_slsa_v1_task_1_w_name = tekton_test.with_ref_name(_slsa_v1_task_1_base, "rpm-ostree")
	slsa_v1_task_1 = tekton_test.with_params(
		_slsa_v1_task_1_w_name,
		[{
			"name": "BUILDER_IMAGE",
			"value": "registry.local/spam:v1.0",
		}],
	)

	_slsa_v1_task_2_base := tekton_test.slsav1_task("rpm-ostree-2")
	_slsa_v1_task_2_w_name = tekton_test.with_ref_name(_slsa_v1_task_2_base, "rpm-ostree")
	slsa_v1_task_2 = tekton_test.with_params(
		_slsa_v1_task_2_w_name,
		[{
			"name": "BUILDER_IMAGE",
			"value": "registry.local/deprecated:v1.0@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd",
		}],
	)

	slsa_v1_attestation := tekton_test.slsav1_attestation([slsa_v1_task_1, slsa_v1_task_2])

	attestations := [slsa_v02_attestation, slsa_v1_attestation]

	expected := {
		# Prefix with an expiration date
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/deprecated:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" starts with \"registry.local/deprecated\" prefix that expires on 2099-01-01T00:00:00Z",
			"effective_on": "2099-01-01T00:00:00Z",
		},
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/deprecated:v1.0@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd\" starts with \"registry.local/deprecated\" prefix that expires on 2099-01-01T00:00:00Z",
			"effective_on": "2099-01-01T00:00:00Z",
		},
		# Prefix not allowed
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/spam:v0.2\" does not start with a pre-approved prefix: registry.local/builder, registry.local/deprecated",
			"effective_on": "2024-03-20T00:00:00Z",
		},
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/spam:v1.0\" does not start with a pre-approved prefix: registry.local/builder, registry.local/deprecated",
			"effective_on": "2024-03-20T00:00:00Z",
		},
		# Not pinned
		{
			"code": "rpm_ostree_task.builder_image_param",
			"msg": "BUILDER_IMAGE \"registry.local/spam:v0.2\" is not pinned to a digest",
			"effective_on": "2024-03-20T00:00:00Z",
		},
		{
			"code": "rpm_ostree_task.builder_image_param",
			"msg": "BUILDER_IMAGE \"registry.local/spam:v1.0\" is not pinned to a digest",
			"effective_on": "2024-03-20T00:00:00Z",
		},
	}

	allowed_prefixes := [
		"registry.local/builder",
		{"value": "registry.local/deprecated", "expires_on": "2099-01-01T00:00:00Z"},
	]

	assertions.assert_equal_results_no_collections(expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data.allowed_rpm_ostree_builder_image_prefixes as allowed_prefixes
}

test_rule_data_failures if {
	rd := {"allowed_rpm_ostree_builder_image_prefixes": [
		# Unexpected type
		["spam"],
		# Missing required object attributes
		{"expires_on": "2030-01-01T00:00:00Z"},
		# Additional attributes not allowed
		{"spam": "maps", "value": "registry.local/repo", "expires_on": "2030-01-01T00:00:00Z"},
		# Incorrect type attributes
		{"value": 0, "expires_on": 1},
	]}

	expected := _both_rule_data_codes({
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 0: Invalid type. Expected: object, given: array",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 0: Must validate at least one schema (anyOf)",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 1: value is required",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 1: Must validate at least one schema (anyOf)",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 2: Additional property spam is not allowed",
			"severity": "warning",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 2: Must validate at least one schema (anyOf)",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 3.expires_on: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 3.value: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.rule_data",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: 3: Must validate at least one schema (anyOf)",
			"severity": "failure",
		},
	})

	assertions.assert_equal_results(expected, rpm_ostree_task.deny) with data.rule_data as rd
}

# RA14-RPM-OSTREE-DATA-SHAPE-001: a present but scalar string
# allowed_rpm_ostree_builder_image_prefixes value must produce a format
# rejection from the v2 rule instead of the format result silently
# disappearing. The prefix consumer cannot match anything against the scalar,
# so its mismatch result remains alongside the format rejection. The legacy
# rule_data stays silent: a builtin error in its schema validation suppresses
# the result, which is the gap the v2 rule closes.
test_rule_data_v2_scalar_string_rejected if {
	attestations := [_pinned_builder_image_attestation]

	expected := {
		{
			"code": "rpm_ostree_task.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" does not start with a pre-approved prefix: ",
			"effective_on": "2024-03-20T00:00:00Z",
		},
	}

	assertions.assert_equal_results(expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data as {"allowed_rpm_ostree_builder_image_prefixes": "registry.local/builder"}

	scalar_number_expected := {
		{
			"code": "rpm_ostree_task.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: integer",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" does not start with a pre-approved prefix: ",
			"effective_on": "2024-03-20T00:00:00Z",
		},
	}
	assertions.assert_equal_results(scalar_number_expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data as {"allowed_rpm_ostree_builder_image_prefixes": 1}
}

# A string containing JSON text is never interpreted as serialized JSON text
# by the v2 rule: "[]" parses as a valid empty prefix list for the legacy
# rule's JSON-text interpretation, but is rejected as a string by the v2 rule.
# A native empty list stays schema-valid and must not acquire a rule_data
# result on either rule.
test_rule_data_v2_json_text_string_rejected if {
	attestations := [_pinned_builder_image_attestation]

	json_text_expected := {
		{
			"code": "rpm_ostree_task.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" does not start with a pre-approved prefix: ",
			"effective_on": "2024-03-20T00:00:00Z",
		},
	}
	assertions.assert_equal_results(json_text_expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data as {"allowed_rpm_ostree_builder_image_prefixes": "[]"}

	# The empty/absent-prefix baseline: the schema has no minItems requirement,
	# so an explicitly empty or absent list is valid and acquires no rule_data
	# result on either rule. The prefix consumer still denies the image,
	# because the empty match comprehension makes every reference mismatch:
	# this contradicts the rule description's claim that an empty list allows
	# any pinned image reference, and is reported separately from EC-2234.
	empty_expected := {{
		"code": "rpm_ostree_task.builder_image_param",
		# regal ignore:line-length
		"msg": "BUILDER_IMAGE \"registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" does not start with a pre-approved prefix: ",
		"effective_on": "2024-03-20T00:00:00Z",
	}}
	assertions.assert_equal_results(empty_expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data as {"allowed_rpm_ostree_builder_image_prefixes": []}
	assertions.assert_equal_results(empty_expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data as {}
}

# A malformed high-priority override above a valid lower-priority list must
# be rejected rather than silently using the lower-priority value.
test_rule_data_v2_precedence if {
	attestations := [_pinned_builder_image_attestation]

	expected := {
		{
			"code": "rpm_ostree_task.rule_data_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_rpm_ostree_builder_image_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
		{
			"code": "rpm_ostree_task.builder_image_param",
			# regal ignore:line-length
			"msg": "BUILDER_IMAGE \"registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" does not start with a pre-approved prefix: ",
			"effective_on": "2024-03-20T00:00:00Z",
		},
	}

	assertions.assert_equal_results(expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data_custom as {"allowed_rpm_ostree_builder_image_prefixes": "registry.local/builder"}
		with data.rule_data as {"allowed_rpm_ostree_builder_image_prefixes": ["registry.local/builder"]}
}

# The valid matching and nonmatching consumer controls keep working alongside
# the v2 format rule.
test_rule_data_v2_consumer_controls if {
	attestations := [_pinned_builder_image_attestation]

	assertions.assert_empty(rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data as {"allowed_rpm_ostree_builder_image_prefixes": ["registry.local/builder"]}

	expected := {{
		"code": "rpm_ostree_task.builder_image_param",
		# regal ignore:line-length
		"msg": "BUILDER_IMAGE \"registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" does not start with a pre-approved prefix: registry.local/other",
		"effective_on": "2024-03-20T00:00:00Z",
	}}
	assertions.assert_equal_results_no_collections(expected, rpm_ostree_task.deny) with input.attestations as attestations
		with data.rule_data as {"allowed_rpm_ostree_builder_image_prefixes": ["registry.local/other"]}
}

# _pinned_builder_image_attestation is an attestation of an rpm-ostree Task
# whose BUILDER_IMAGE is pinned to a digest.
_pinned_builder_image_attestation := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{
			"name": "rpm-ostree-p",
			"ref": {"kind": "Task", "name": "rpm-ostree"},
			# regal ignore:line-length
			"invocation": {"parameters": {"BUILDER_IMAGE": "registry.local/builder:v0.2@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"}},
		}]},
	},
}}

# The v2 twin of rule_data reports the same diagnostics under a _v2 code, so
# expected sets are shared across both rules.
_both_rule_data_codes(results) := {result |
	some base in results
	some code in {"rpm_ostree_task.rule_data", "rpm_ostree_task.rule_data_v2"}
	result := object.union(base, {"code": code})
}
