#
# METADATA
# title: Tekton task kind checks
# description: >-
#   Policies to verify that a Tekton task definition has the expected
#   value for kind.
#
package kind

import rego.v1

import data.lib.utils as lib

expected_kind := "Task"

# METADATA
# title: Task definition has expected kind
# description: >-
#   Confirm the task definition has the kind "Task".
# custom:
#   short_name: expected_kind
#   failure_msg: Unexpected kind '%s' for task definition
#
deny contains result if {
	expected_kind != input.kind
	result := lib.result_helper(rego.metadata.chain(), [input.kind])
}

# METADATA
# title: Kind field is present in task definition
# description: >-
#   Confirm the task definition includes the kind field.
# custom:
#   short_name: kind_present
#   failure_msg: Required field 'kind' not found
#
deny contains result if {
	not input.kind
	result := lib.result_helper(rego.metadata.chain(), [])
}
