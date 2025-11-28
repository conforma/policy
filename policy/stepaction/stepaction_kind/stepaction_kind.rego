#
# METADATA
# title: Tekton StepAction kind checks
# description: >-
#   Policies to verify that a Tekton StepAction definition has the expected
#   value for kind.
#
package stepaction_kind

import rego.v1

import data.lib

# METADATA
# title: StepAction definition has expected kind
# description: >-
#   Confirm the StepAction definition has the kind "StepAction".
# custom:
#   short_name: valid
#   failure_msg: Unexpected kind %q for StepAction definition
#
deny contains result if {
	k := object.get(input, "kind", "")
	k != "StepAction"
	result := lib.result_helper(rego.metadata.chain(), [k])
}
