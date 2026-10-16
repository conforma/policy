#
# METADATA
# title: Pipeline definition sanity checks
# description: >-
#   Policies to confirm the Tekton Pipeline definition has the expected kind.
#
package basic

import rego.v1

import data.lib.metadata

expected_kind := "Pipeline"

# (Not sure if we need this, but I'm using it to test the docs build.)

# METADATA
# title: Pipeline definition has expected kind
# description: >-
#   Confirm that the pipeline definition has the kind "Pipeline". A missing
#   `kind` is treated the same as an unexpected one so that a malformed
#   pipeline definition cannot silently bypass this check.
# custom:
#   short_name: expected_kind
#   failure_msg: Unexpected kind '%s' for pipeline definition
#
deny contains result if {
	kind := object.get(input, "kind", "")
	expected_kind != kind
	result := metadata.result_helper(rego.metadata.chain(), [kind])
}
