package lib.sets

import rego.v1

# It's fairly idiomatic rego to do this inline but these
# can make your code a little more readable in some cases
#
to_set(arr) := {member | some member in arr}

to_array(s) := [member | some member in s]

# Without the in keyword it could be done like this:
#  needle == haystack[_]
#
included_in(needle, haystack) if {
	needle in haystack
}

# Return true if any of the needles are found in the haystack
any_included_in(needles, haystack) if {
	# (Set intersection)
	count(to_set(needles) & to_set(haystack)) > 0
}

# Return true if all of the needles are found in the haystack
all_included_in(needles, haystack) if {
	# (Set difference)
	count(to_set(needles) - to_set(haystack)) == 0
}

# Return true if none of the needles are found in the haystack
none_included_in(needles, haystack) if {
	not any_included_in(needles, haystack)
}

# Return true if any of the needles are missing from the haystack
any_not_included_in(needles, haystack) if {
	not all_included_in(needles, haystack)
}
