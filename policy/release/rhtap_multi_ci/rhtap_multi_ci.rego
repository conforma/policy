#
# METADATA
# title: RHTAP Multi-CI
# description: >-
#   Checks for images built using an RHTAP build pipeline in either Jenkins,
#   GitLab or GitHub. RHTAP pipelines are defined under
#   https://github.com/redhat-appstudio/tssc-sample-templates/tree/main/skeleton/ci
#
package rhtap_multi_ci

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.strings
import data.lib.json as j

# METADATA
# title: SLSA Provenance Attestation Found
# description: >-
#   Verify an attestation created by the RHTAP Multi-CI build pipeline is present.
# custom:
#   short_name: attestation_found
#   failure_msg: "A SLSA v1.0 provenance with one of the following RHTAP Multi-CI
#     build types was not found: %s."
#   solution: >-
#     It appears the build pipeline did not create the expected SLSA provenance
#     attestation. Check for relevant error messages in the 'cosign-sign-attest'
#     pipeline step logs.
#   collections:
#   - rhtap-multi-ci
#   # For compatibility. These will be removed these soon.
#   - rhtap-github
#   - rhtap-gitlab
#   - rhtap-jenkins
#
deny contains result if {
	count(_attestations) < 1
	result := metadata.result_helper(rego.metadata.chain(), [strings.quoted_values_string(_known_build_types)])
}

# METADATA
# title: SLSA Provenance Attestation Format
# description: >-
#   Confirm the attestation created by the RHTAP Multi-CI build pipeline matches the
#   expected format.
# custom:
#   short_name: attestation_format
#   failure_msg: "RHTAP %s attestation problem: %s"
#   solution: >-
#     This check looks for some fields expected to be present in the SLSA attestation. Modifying
#     the scripts that produce the attestation predicate might cause this to fail. See also
#     the `att-predicate-*.sh` scripts at https://github.com/redhat-appstudio/tssc-dev-multi-ci/tree/main/rhtap
#   collections:
#   - rhtap-multi-ci
#   # For compatibility. These will be removed these soon.
#   - rhtap-github
#   - rhtap-gitlab
#   - rhtap-jenkins
#   depends_on:
#   - rhtap_multi_ci.attestation_found
#
deny contains result if {
	some att in _attestations
	some ci_type in _known_ci_types
	att.statement.predicate.buildDefinition.buildType == _build_type(ci_type)
	some schema_error in j.validate_schema(att.statement.predicate, _predicate_schema(ci_type))
	result := metadata.result_helper(rego.metadata.chain(), [ci_type, schema_error.message])
}

# -----------------------------------------------------------------------------

# Common to each ci type
_predicate_schema_base := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "object",
	"required": ["runDetails"],
	"properties": {"runDetails": {
		"type": "object",
		"required": ["builder", "metadata"],
		"properties": {
			"metadata": {
				"type": "object",
				"required": ["invocationID"],
				"properties": {"invocationID": {"type": "string", "minLength": 1}},
			},
			"builder": {
				"type": "object",
				"required": ["id"],
				"properties": {"id": {"type": "string", "minLength": 1}},
			},
		},
	}},
}

# See https://github.com/redhat-appstudio/tssc-dev-multi-ci/blob/main/rhtap/att-predicate-jenkins.sh
_predicate_schema("jenkins") := json.patch(_predicate_schema_base, [
	# Check runDetails.builder.version is present and is an object
	{"op": "add", "path": "/properties/runDetails/properties/builder/required/1", "value": "version"},
	{"op": "add", "path": "/properties/runDetails/properties/builder/properties/version", "value": {"type": "object"}},
])

# See https://github.com/redhat-appstudio/tssc-dev-multi-ci/blob/main/rhtap/att-predicate-github.sh
# (Currently no extra schema checks other than the common checks)
_predicate_schema("github") := json.patch(_predicate_schema_base, [])

# See https://github.com/redhat-appstudio/tssc-dev-multi-ci/blob/main/rhtap/att-predicate-gitlab.sh
# (Currently no extra schema checks other than the common checks)
_predicate_schema("gitlab") := json.patch(_predicate_schema_base, [])

# -----------------------------------------------------------------------------

_known_build_types := [_build_type(known_ci_type) | some known_ci_type in _known_ci_types]

_build_type(ci_type) := sprintf("https://redhat.com/rhtap/slsa-build-types/%s-build/v1", [ci_type])

# RHTAP Multi-CI currently supports these environments:
_known_ci_types := ["jenkins", "github", "gitlab", "azure"]

# Just the potentially relevant attestations
_attestations := [att |
	some att in _all_attestations

	# Beware we are not supporting SLSA formats other than v1.0 here
	att.statement.predicateType == _slsa_provenance_predicate_type_v1

	# Just the RHTAP Multi-CI build types
	some known_build_type in _known_build_types
	att.statement.predicate.buildDefinition.buildType == known_build_type
]

# Standard predicate type for SLSA V1.0
_slsa_provenance_predicate_type_v1 := "https://slsa.dev/provenance/v1"

# The actual raw attestation is found under the 'statement' key.
# See https://conforma.dev/docs/cli/policy_input.html#_validate_image
_all_attestations := input.attestations
