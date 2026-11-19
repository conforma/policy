#
# METADATA
# title: Tekton StepAction images policies
# description: >-
#   This package ensures that a StepAction definition contains a valid and allowed value for the
#   image reference.
#
package stepaction_image

import rego.v1

import data.lib.metadata
import data.lib.rule_data

import data.lib.json as j
import data.lib.k8s

# METADATA
# title: Image is accessible
# description: >-
#   Confirm the container image used in the StepTemplate is accessible.
# custom:
#   short_name: accessible
#   failure_msg: Image ref %q is inaccessible
#   solution: >-
#     Make sure the container image used in the StepTemplate is pushed to the registry and that it
#     can be fetched.
#
deny contains result if {
	image_ref := input.spec.image
	not ec.oci.image_manifest(image_ref)

	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[image_ref],
		image_ref,
	)
}

# METADATA
# title: Image comes from permitted registry
# description: >-
#   Confirm the StepAction uses a container image with a URL that matches one of the prefixes in the
#   provided list of allowed step image registry prefixes. The list is customizeable via the
#   `allowed_step_image_registry_prefixes` rule data key.
# custom:
#   short_name: permitted
#   failure_msg: Image ref %q is disallowed
#   solution: >-
#     Make sure the container image used comes from an approved registry.
#   collections:
#   - redhat_security
#
deny contains result if {
	image_ref := input.spec.image
	allowed_registry_prefixes := rule_data.get(_rule_data_key)
	not ref_permitted(image_ref, allowed_registry_prefixes)

	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[image_ref],
		k8s.name_version(input),
	)
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the `allowed_step_image_registry_prefixes` rule data is provided.
# custom:
#   short_name: rule_data
#   failure_msg: "%s"
#   solution: >-
#     Make sure the xref:cli:ROOT:configuration.adoc#_data_sources[data sources] contains a key
#     'allowed_step_image_registry_prefixes' that contains a list of approved registries.
#   collections:
#   - redhat_security
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

# METADATA
# title: Rule data provided (v2)
# description: >-
#   Confirm the `allowed_step_image_registry_prefixes` rule data is provided. Unlike rule_data,
#   a present value of the wrong type (for example a scalar or a string containing JSON text) is
#   rejected instead of silently skipping the check.
# custom:
#   short_name: rule_data_v2
#   failure_msg: "%s"
#   solution: >-
#     Make sure the xref:cli:ROOT:configuration.adoc#_data_sources[data sources] contains a key
#     'allowed_step_image_registry_prefixes' that contains a list of approved registries.
#   collections:
#   - redhat_security
#   effective_on: 2027-01-11T00:00:00Z
#
deny contains result if {
	some e in _rule_data_errors_v2
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

ref_permitted(image_ref, allowed_prefixes) if {
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
}

_rule_data_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "array",
	"items": {"type": "string"},
	"uniqueItems": true,
	"minItems": 1,
}

_rule_data_errors contains error if {
	some e in j.validate_schema(rule_data.get(_rule_data_key), _rule_data_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

# _rule_data_errors_v2 mirrors _rule_data_errors but validates the value as
# native rule data: a present scalar value is reported as a format violation
# instead of raising a builtin error that suppresses the result, and a string
# is never interpreted as serialized JSON.
_rule_data_errors_v2 contains error if {
	some e in j.validate_schema_native(rule_data.get(_rule_data_key), _rule_data_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_key := "allowed_step_image_registry_prefixes"
