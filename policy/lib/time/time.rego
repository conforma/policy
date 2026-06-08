package lib.time

import rego.v1

import data.lib.arrays

# A default value in the past. Could be whatever but beware you'll have to
# update a bunch of tests if you change it.
#
default_effective_on := "2022-01-01T00:00:00Z"

# This supports finding an effective_on date in multiple scopes, giving
# precedence to the narrowest scope. Let's keep it that way even though
# currently we're not using any scopes except for the rule scope.
#
when(metadata_chain) := effective_on if {
	scope_precedence := ["rule", "document", "package"]
	all_effective_on := [metadata.annotations.custom.effective_on |
		some metadata in metadata_chain
		metadata.annotations.scope in scope_precedence
	]

	# Use the first one found in scope_precedence or fall back to the default
	# value if effective_on was not found in annotations
	effective_on := array.concat(all_effective_on, [default_effective_on])[0]
}

# Use the nanosecond epoch defined in the policy config if it is
# present, otherwise use the real current time
effective_current_time_ns := now_ns if {
	data.config
	now_ns := object.get(data.config, ["policy", "when_ns"], time.now_ns())
}

# Handle edge case where data.config is not present
# (We can't do `object.get(data, ...)` for some reason)
effective_current_time_ns := now_ns if {
	not data.config
	now_ns := time.now_ns()
}

# most_current returns the first item in the given list of objects where
# effective_on is NOT in the future (less than or equal to now). Items that do
# not define the effective_on attribute are ignored. If the given list of
# items is empty, or no items are current, most_current does not produce a
# value.
most_current(items) := item if {
	current := [i |
		some i in items
		i.effective_on
		not time.parse_rfc3339_ns(i.effective_on) > effective_current_time_ns
	]

	item := newest(current)
}

# newest returns the newest item by `effective_on`. Assumes same date format and
# time-zone for `effective_on` field.
newest(items) := item if {
	ordered := arrays.sort_by("effective_on", items)

	item := ordered[count(ordered) - 1]
}

# Safely parse an RFC 3339 date string to nanoseconds.
# Returns undefined when date_str is empty or unparseable.
parse_rfc3339_safe(date_str) := ns if {
	date_str != ""
	ns := time.parse_rfc3339_ns(date_str)
}

# Returns true when date_str is non-empty but fails to parse as RFC 3339.
is_date_invalid(date_str) if {
	date_str != ""
	not parse_rfc3339_safe(date_str)
}
