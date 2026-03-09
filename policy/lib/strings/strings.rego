package lib.strings

import rego.v1

quoted_values_string(value_list) := result if {
	quoted_list := [quoted_item |
		some item in value_list
		quoted_item := sprintf("'%s'", [item])
	]

	result := concat(", ", quoted_list)
}

pluralize_maybe(set_or_list, singular_word, plural_word) := singular_word if {
	# One item, use the singular word
	count(set_or_list) == 1
} else := sprintf("%ss", [singular_word]) if {
	# No plural word provided, make one by adding an "s"
	plural_word in {null, ""}
	# Use provided plural word
} else := plural_word
