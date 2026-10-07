#
# METADATA
# title: Schedule related checks
# description: >-
#   Rules that verify the current date conform to a given schedule.
#
package schedule

import rego.v1

import data.lib
import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data

# METADATA
# title: Weekday Restriction
# description: >-
#   Check if the current weekday is allowed based on the rule data value from the key
#   `disallowed_weekdays`. By default, the list is empty in which case *any* weekday is
#   allowed. This check is enforced only for a "release" or "production"
#   pipeline, as determined by the value of the `pipeline_intention` rule data.
# custom:
#   short_name: weekday_restriction
#   pipeline_intention:
#   - release
#   - production
#   failure_msg: '%s is a disallowed weekday: %s'
#   solution: Try again on a different weekday.
#   collections:
#   - redhat
#
deny contains result if {
	metadata.pipeline_intention_match(rego.metadata.chain())
	today := lower(time.weekday(lib.time.effective_current_time_ns))
	disallowed := {lower(w) | some w in rule_data.get("disallowed_weekdays")}
	count(disallowed) > 0
	today in disallowed
	result := metadata.result_helper(rego.metadata.chain(), [today, concat(", ", disallowed)])
}

# METADATA
# title: Date Restriction
# description: >-
#   Check if the current UTC date is disallowed by the unique string array
#   `disallowed_dates`. For example:
#   `["2026-12-31", "from:2026-12-19 to:2026-12-31", "*-12-31",
#   "from:*-12-20 to:*-01-06"]`. Only the year may be `*`.
#   Ranges must use exact lowercase `from:X to:Y` syntax with one space;
#   surrounding or extra whitespace, alternate order, and case variants are
#   invalid. Concrete range ends must be later than their starts, and both
#   endpoints are included. A later wildcard month/day end stays in one year;
#   an earlier end wraps into the next year.
#   Wildcard ranges use the effective UTC date, including
#   `config.policy.when_ns` overrides. An early-January date uses the
#   occurrence begun in the prior December. Mixed concrete/wildcard endpoints,
#   equal wildcard endpoints, and `*-02-29` are invalid. Concrete February 29
#   is valid only in an explicit leap year.
#   The list is empty by default. This check runs only for a "release" or
#   "production" pipeline, as determined by `pipeline_intention`.
# custom:
#   short_name: date_restriction
#   pipeline_intention:
#   - release
#   - production
#   failure_msg: '%s is a disallowed date: %s'
#   solution: Try again on a different day.
#   collections:
#   - redhat
#
deny contains result if {
	metadata.pipeline_intention_match(rego.metadata.chain())
	today := time.format([lib.time.effective_current_time_ns, "UTC", "2006-01-02"])
	disallowed := rule_data.get("disallowed_dates")
	is_array(disallowed)
	some date in disallowed
	_date_spec_matches(date, today)
	result := metadata.result_helper(rego.metadata.chain(), [today, concat(", ", disallowed)])
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm schedule rule data keys use the expected formats. `disallowed_dates` must be a unique
#   array of strings; see Date Restriction for supported date and range formats.
#   `disallowed_weekdays` remains a unique array of weekday names.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - redhat
#   - policy_data
#
deny contains result if {
	# (For this one let's do it always)
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_rule_data_errors contains error if {
	key := "disallowed_weekdays"

	# JSON Schema doesn't allow case insensitive enum types. So here we define a list of all the
	# weekdays as "title-case", lower case, and upper case.
	titled_weekdays := ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
	weekdays := array.concat(
		array.concat(
			titled_weekdays,
			[lower(d) | some d in titled_weekdays],
		),
		[upper(d) | some d in titled_weekdays],
	)

	some e in j.validate_schema(
		rule_data.get(key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"enum": weekdays},
			"uniqueItems": true,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	# IMPORTANT: Although the JSON schema spec does allow specifying a regular expression to match
	# values, via the "pattern" attribute, rego's JSON schema validator does not:
	# https://github.com/open-policy-agent/opa/issues/6089
	key := "disallowed_dates"

	some e in j.validate_schema(
		_schema_document(rule_data.get(key)),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	key := "disallowed_dates"
	dates := rule_data.get(key)
	is_array(dates)
	some index, date in dates
	not _valid_date_spec(date)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %d: Invalid date %q", [key, index, date]),
		"severity": "failure",
	}
}

# Validate concrete/wildcard singles and ranges, e.g. '2026-12-31', '*-12-31',
# 'from:2026-12-19 to:2026-12-31', and 'from:*-12-20 to:*-01-06'.
# Reject invalid dates, reversed concrete bounds, mixed endpoints, and equal wildcard bounds.
_valid_date_spec(date) if {
	_valid_date(date)
}

_valid_date_spec(date) if {
	_wildcard_month_day(date)
}

_valid_date_spec(date) if {
	bounds := _range_bounds(date)
	start_date := bounds[0]
	_valid_date(start_date)
	_valid_date(bounds[1])
	start_date < bounds[1]
}

_valid_date_spec(date) if {
	_wildcard_range_month_days(date)
}

# Encode primitive scalars so JSON Schema reports root-type errors; pass other values through.
_schema_document(value) := json.marshal(value) if {
	type_name(value) in {"boolean", "number", "string"}
} else := value

# Accept only zero-padded 'YYYY-MM-DD' strings that represent real calendar dates.
_valid_date(date) if {
	is_string(date)
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, date)
	time.parse_ns("2006-01-02", date)
}

# Extract bounds from exact lowercase 'from:X to:Y' input with one separating space.
# Malformed labels, spacing, or missing endpoints leave this function undefined.
_range_bounds(date) := [start_date, end_date] if {
	is_string(date)
	parts := split(date, " ")
	count(parts) == 2
	start_parts := split(parts[0], ":")
	count(start_parts) == 2
	start_parts[0] == "from"
	end_parts := split(parts[1], ":")
	count(end_parts) == 2
	end_parts[0] == "to"
	start_date := start_parts[1]
	end_date := end_parts[1]
}

# Validate a year-wildcard single or endpoint, e.g. '*-12-31'.
# Reject invalid MM-DD values and '*-02-29'.
_wildcard_month_day(date) := month_day if {
	is_string(date)
	parts := split(date, "-")
	count(parts) == 3
	parts[0] == "*"
	regex.match(`^[0-9]{2}$`, parts[1])
	regex.match(`^[0-9]{2}$`, parts[2])
	date != "*-02-29"
	time.parse_ns("2006-01-02", sprintf("2000-%s-%s", [parts[1], parts[2]]))
	month_day := sprintf("%s-%s", [parts[1], parts[2]])
}

# Accept distinct wildcard bounds such as 'from:*-12-20 to:*-01-06'; reject equal
# bounds such as 'from:*-07-02 to:*-07-02'.
_wildcard_range_month_days(date) := [start_month_day, end_month_day] if {
	bounds := _range_bounds(date)
	start_month_day := _wildcard_month_day(bounds[0])
	end_month_day := _wildcard_month_day(bounds[1])
	start_month_day != end_month_day
}

# Match inclusive month-day intervals: 07-03 is inside 07-02 to 07-04.
# A wrapped 12-20 to 01-06 interval also includes 01-03.
_wildcard_range_matches(from_month_day, to_month_day, current_month_day) if {
	from_month_day <= to_month_day
	from_month_day <= current_month_day
	current_month_day <= to_month_day
}

_wildcard_range_matches(from_month_day, to_month_day, current_month_day) if {
	from_month_day > to_month_day
	from_month_day <= current_month_day
}

_wildcard_range_matches(from_month_day, to_month_day, current_month_day) if {
	from_month_day > to_month_day
	current_month_day <= to_month_day
}

# Match specifications against today's UTC date, e.g. '2026-12-31' on that day
# or 'from:*-12-20 to:*-01-06' on 2042-01-03.
_date_spec_matches(date, today) if {
	date == today
}

_date_spec_matches(date, today) if {
	month_day := _wildcard_month_day(date)
	month_day == substring(today, 5, 5)
}

_date_spec_matches(date, today) if {
	_valid_date_spec(date)
	bounds := _range_bounds(date)
	_valid_date(bounds[0])
	_valid_date(bounds[1])
	bounds[0] <= today
	today <= bounds[1]
}

_date_spec_matches(date, today) if {
	month_days := _wildcard_range_month_days(date)
	_wildcard_range_matches(month_days[0], month_days[1], substring(today, 5, 5))
}
