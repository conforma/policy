#
# METADATA
# title: Pipeline definition sanity checks
# description: >-
#   Policies to confirm the Tekton Pipeline definition has the expected kind.
#
package basic

import rego.v1

import data.lib.utils as lib

expected_kind := "Pipeline"

# (Not sure if we need this, but I'm using it to test the docs build.)

# Fixme: It doesn't fail if the kind key is entirely missing..

# METADATA
# title: Pipeline definition has expected kind
# description: >-
#   Confirm that the pipeline definition has the kind "Pipeline".
# custom:
#   short_name: expected_kind
#   failure_msg: Unexpected kind '%s' for pipeline definition
#
deny contains result if {
	expected_kind != input.kind
	result := lib.result_helper(rego.metadata.chain(), [input.kind])
}
