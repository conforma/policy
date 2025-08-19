package lib

import rego.v1

import data.lib.time as time_lib

# The first entry in the chain always points to the active rule, even if it has
# no declared annotations (in which case the annotations member is not present).
# Thus, result_helper assumes every rule defines annotations. At the very least
# custom.short_name must be present.
_rule_annotations(chain) := chain[0].annotations

result_helper(chain, failure_sprintf_params) := result if {
	with_collections := {"collections": _rule_annotations(chain).custom.collections}
	result := object.union(_basic_result(chain, failure_sprintf_params), with_collections)
} else := result if {
	result := _basic_result(chain, failure_sprintf_params)
}

result_helper_with_term(chain, failure_sprintf_params, term) := object.union(
	result_helper(chain, failure_sprintf_params),
	{"term": term},
)

result_helper_with_severity(chain, failure_sprintf_params, severity) := object.union(
	result_helper(chain, failure_sprintf_params),
	{"severity": severity},
)

_basic_result(chain, failure_sprintf_params) := {
	"code": _code(chain),
	"msg": sprintf(_rule_annotations(chain).custom.failure_msg, failure_sprintf_params),
	"effective_on": time_lib.when(chain),
}

_code(chain) := code if {
	rule_path := chain[0].path
	pkg_name := _pkg_name(rule_path)

	# Todo someday maybe: Conftest supports denies named deny_some_name,
	# so we could use that format and ditch the short name annotation.
	rule_name := _rule_annotations(chain).custom.short_name

	# Put them together
	code := sprintf("%s.%s", [pkg_name, rule_name])
}

_pkg_name(rule_path) := name if {
	# "data" is automatically added by rego.
	p1 := _left_strip_elements(["data"], rule_path)

	# Remove the actual rule name as that is not part of the package.
	p2 := _right_strip_elements(["deny"], p1)
	p3 := _right_strip_elements(["warn"], p2)

	name := concat(".", p3)
}

_left_strip_elements(items_to_strip, list) := new_list if {
	items_to_strip_count := count(items_to_strip)
	array.slice(list, 0, items_to_strip_count) == items_to_strip
	new_list := array.slice(list, items_to_strip_count, count(list))
} else := list

_right_strip_elements(items_to_strip, list) := array.reverse(_left_strip_elements(items_to_strip, array.reverse(list)))
