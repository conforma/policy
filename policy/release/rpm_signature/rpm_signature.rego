#
# METADATA
# title: RPM Signature
# description: >-
#   This package provides rules for verifying the signatures of RPMs identified in the the SLSA
#   Provenance attestation.
#
package rpm_signature

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.rule_data
import data.lib.json as j

# METADATA
# title: Allowed RPM signature key
# description: >-
#   The SLSA Provenance attestation for the image is inspected to ensure RPMs have been signed by
#   pre-defined set of signing keys. The list of signing keys can be set via the
#   `allowed_rpm_signature_keys` rule data. Use the special value "unsigned" to allow unsigned RPMs.
# custom:
#   short_name: allowed
#   failure_msg: "Signing key %q is not one of the allowed keys: %s"
#   solution: >-
#     Make sure to use RPMs that have been signed by the expected signing key. An RPM lacking such
#     signature, usually indicated the RPM is not ready for consumption.
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: 2024-10-05T00:00:00Z
#
deny contains result if {
	some key in _signature_keys
	not key in _allowed_rpm_signature_keys
	result := metadata.result_helper_with_term(rego.metadata.chain(), [key, _allowed_rpm_signature_keys], key)
}

# METADATA
# title: Result format
# description: >-
#   Confirm the format of the RPMS_DATA result is in the expected format.
# custom:
#   short_name: result_format
#   failure_msg: '%s'
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: 2024-10-05T00:00:00Z
#
deny contains result if {
	some error in _result_format_errors
	result := metadata.result_helper(rego.metadata.chain(), [error])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected `allowed_rpm_signature_keys` rule data key has been provided in the
#   expected format.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#   effective_on: 2024-10-05T00:00:00Z
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_allowed_rpm_signature_keys := rule_data.rule_data("allowed_rpm_signature_keys")

_signature_keys contains key if {
	some result in lib.results_named(_rpms_data_result_name)
	some key, num in result.value.keys
	num > 0
}

_result_format_errors contains msg if {
	some result in lib.results_named(_rpms_data_result_name)

	value := json.marshal(result.value)
	some violation in json.match_schema(
		value,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"properties": {"keys": {
				"type": "object",
				"patternProperties": {".*": {"type": "integer"}},
			}},
			"additionalProperties": true,
		},
	)[1]
	msg := sprintf("Task result has unexpected format: %s", [violation.error])
}

_rule_data_errors contains error if {
	some e in j.validate_schema(
		_allowed_rpm_signature_keys,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)
	error := {
		"message": sprintf("Rule data has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	some key in _allowed_rpm_signature_keys
	not _is_valid_key(key)
	error := {
		"message": sprintf("Unexpected format of signing key %q", [key]),
		"severity": "failure",
	}
}

_is_valid_key(key) if {
	# "unsigned" is a special value that indicates no signatures.
	key == "unsigned"
} else if {
	# Rego's JSON Schema processor doesn't seem to handle "pattern". So we do it "manually" here :(
	regex.match(`[a-fA-F0-9]{16}`, key)
}

_rpms_data_result_name := "RPMS_DATA"
