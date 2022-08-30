package lib

import future.keywords.in

item_in_list(item, list_or_set) {
	# Without the in keyword it could be done like this:
	# list_or_set[_] == item
	item in list_or_set
}

list_includes_item(list_or_set, item) {
	item_in_list(item, list_or_set)
}

quoted_values_string(value_list) = result {
	quoted_list := [quoted_item |
		item := value_list[_]
		quoted_item := sprintf("'%s'", [item])
	]

	result := concat(", ", quoted_list)
}
