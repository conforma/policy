package lib

import rego.v1

# The first entry in the chain always points to the active rule, even if it has
# no declared annotations (in which case the annotations member is not present).
# Thus, result_helper assumes every rule defines annotations. At the very least
# custom.short_name must be present.
_rule_annotations(chain) := chain[0].annotations

release_restrictions_apply(chain) if {
	rule_data("pipeline_intention") in {intention | some intention in _rule_annotations(chain).custom.pipeline_intention}
} else := false
