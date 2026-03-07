#
# METADATA
# title: Buildah build task
# description: >-
#   This package is responsible for verifying the buildah build task
#
package buildah_build_task

import rego.v1

import data.lib
import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data
import data.lib.tekton

# METADATA
# title: Buildah task uses a local Dockerfile
# description: >-
#   Verify the Dockerfile used in the buildah task was not
#   fetched from an external source.
# custom:
#   short_name: buildah_uses_local_dockerfile
#   failure_msg: DOCKERFILE param value (%s) is an external source
#   solution: >-
#     Make sure the 'DOCKERFILE' parameter does not come from an external source.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some dockerfile_param in _dockerfile_params
	_not_allowed_prefix(dockerfile_param)
	result := metadata.result_helper(rego.metadata.chain(), [dockerfile_param])
}

# METADATA
# title: ADD_CAPABILITIES parameter
# description: >-
#   Verify the ADD_CAPABILITIES parameter of a builder Tasks was not used.
# custom:
#   short_name: add_capabilities_param
#   failure_msg: ADD_CAPABILITIES parameter is not allowed
#   solution: >-
#     The ADD_CAPABILITIES parameter is not allowed for most container image builds. This, however,
#     might be required for certain build types, e.g. flatpaks. Either unset the parameter or use a
#     policy config that excludes this policy rule.
#   collections:
#   - redhat
#   effective_on: 2024-08-31T00:00:00Z
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some param in _add_capabilities_params
	trim_space(param) != ""
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: PLATFORM parameter
# description: >-
#   Verify the value of the PLATFORM parameter of a builder Task is allowed by matching against a
#   list of disallowed patterns. The list of patterns can be customized via the
#   `disallowed_platform_patterns` rule data key. If empty, all values are allowed.
# custom:
#   short_name: platform_param
#   failure_msg: PLATFORM parameter value %q is disallowed by regex %q
#   solution: Use a different PLATFORM value that is not disallowed by the policy config.
#   collections:
#   - redhat
#   effective_on: 2024-09-01T00:00:00Z
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some param in _platform_params
	some pattern in rule_data.rule_data(_plat_patterns_rule_data_key)
	regex.match(pattern, param)
	result := metadata.result_helper(rego.metadata.chain(), [param, pattern])
}

# METADATA
# title: disallowed_platform_patterns format
# description: >-
#   Confirm the `disallowed_platform_patterns` rule data, if provided matches the expected format.
# custom:
#   short_name: disallowed_platform_patterns_pattern
#   failure_msg: "%s"
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	some error in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
}

# METADATA
# title: PRIVILEGED_NESTED parameter
# description: >-
#   Verify the PRIVILEGED_NESTED parameter of a builder Tasks was not set to `true`.
# custom:
#   short_name: privileged_nested_param
#   failure_msg: setting PRIVILEGED_NESTED parameter to true is not allowed
#   solution: >-
#     Setting PRIVILEGED_NESTED parameter to true is not allowed for most container
#     image builds. Either set the parameter value to false or use a policy config
#     that excludes this policy rule.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some param in _privileged_nested_params
	trim_space(param) == "true"
	result := metadata.result_helper(rego.metadata.chain(), [])
}

_not_allowed_prefix(search) if {
	not_allowed_prefixes := ["http://", "https://"]
	some not_allowed_prefix in not_allowed_prefixes
	startswith(search, not_allowed_prefix)
}

_buildah_tasks contains task if {
	some att in lib.pipelinerun_attestations
	some task in tekton.build_tasks(att)
}

_dockerfile_params contains param if {
	some buildah_task in _buildah_tasks
	param := tekton.task_param(buildah_task, "DOCKERFILE")
}

_add_capabilities_params contains param if {
	some buildah_task in _buildah_tasks
	param := tekton.task_param(buildah_task, "ADD_CAPABILITIES")
}

_platform_params contains param if {
	some buildah_task in _buildah_tasks
	param := tekton.task_param(buildah_task, "PLATFORM")
}

_privileged_nested_params contains param if {
	some buildah_task in _buildah_tasks
	param := tekton.task_param(buildah_task, "PRIVILEGED_NESTED")
}

# Verify disallowed_platform_patterns is a list of strings. Empty list is fine.
_rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.rule_data(_plat_patterns_rule_data_key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_plat_patterns_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

# Verify items in the disallowed_platform_patterns list are valid regular expressions.
_rule_data_errors contains error if {
	# We could use `"pattern": "regex"` in the JSON schema. However, rego doesn't fully support all
	# regex features. This ensures that the regexes provides are valid within the context of rego.
	some r in rule_data.rule_data(_plat_patterns_rule_data_key)
	not regex.is_valid(r)
	error := {
		"message": sprintf("%q is not a valid regular expression in rego", [r]),
		"severity": "failure",
	}
}

_plat_patterns_rule_data_key := "disallowed_platform_patterns"
