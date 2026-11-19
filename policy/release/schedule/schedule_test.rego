package schedule_test

import rego.v1

import data.lib.assertions
import data.schedule

test_no_restriction_by_default if {
	assertions.assert_empty(schedule.deny)
	assertions.assert_empty(schedule.deny) with data.rule_data as date_rule_data([])
}

test_weekday_restriction if {
	_rule_data := weekday_rule_data(["friday", "saturday", "sunday"])

	assertions.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as monday

	assertions.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as tuesday

	assertions.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as wednesday

	assertions.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as thursday

	friday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "friday is a disallowed weekday: friday, saturday, sunday",
	}}
	assertions.assert_equal_results(schedule.deny, friday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as friday

	saturday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "saturday is a disallowed weekday: friday, saturday, sunday",
	}}
	assertions.assert_equal_results(schedule.deny, saturday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as saturday

	sunday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "sunday is a disallowed weekday: friday, saturday, sunday",
	}}
	assertions.assert_equal_results(schedule.deny, sunday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as sunday
}

test_weekday_restriction_case_insensitive if {
	violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "friday is a disallowed weekday: friday",
	}}

	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as weekday_rule_data(["FRIDAY"])
		with data.config.policy.when_ns as friday
	assertions.assert_empty(schedule.deny) with data.rule_data as weekday_rule_data(["FRIDAY"])
		with data.config.policy.when_ns as monday

	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as friday
	assertions.assert_empty(schedule.deny) with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as monday
}

test_date_restriction if {
	violation := {{
		"code": "schedule.date_restriction",
		"msg": "2023-01-01 is a disallowed date: 2023-01-01",
	}}
	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-01-01T00:00:00Z")

	assertions.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-01-02T00:00:00Z")
	assertions.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-02-01T00:00:00Z")
	assertions.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2024-01-01T00:00:00Z")
	assertions.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2024-02-03T00:00:00Z")
}

test_date_restriction_range if {
	specification := "from:2026-12-19 to:2026-12-31"
	d := date_rule_data([specification])

	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2026-12-18")

	start_violation := {{
		"code": "schedule.date_restriction",
		"msg": sprintf("2026-12-19 is a disallowed date: %s", [specification]),
	}}
	assertions.assert_equal_results(schedule.deny, start_violation) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2026-12-19")

	interior_violation := {{
		"code": "schedule.date_restriction",
		"msg": sprintf("2026-12-25 is a disallowed date: %s", [specification]),
	}}
	assertions.assert_equal_results(schedule.deny, interior_violation) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2026-12-25")

	end_violation := {{
		"code": "schedule.date_restriction",
		"msg": sprintf("2026-12-31 is a disallowed date: %s", [specification]),
	}}
	assertions.assert_equal_results(schedule.deny, end_violation) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2026-12-31")

	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2027-01-01")
}

test_date_restriction_cross_year_range if {
	specification := "from:2026-12-20 to:2027-01-06"
	violation := {{
		"code": "schedule.date_restriction",
		"msg": sprintf("2027-01-01 is a disallowed date: %s", [specification]),
	}}

	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as date_rule_data([specification])
		with data.config.policy.when_ns as _rfc_time_helper("2027-01-01")
}

test_date_restriction_overlapping_ranges if {
	dates := [
		"2026-12-25",
		"from:2026-12-19 to:2026-12-31",
		"from:2026-12-20 to:2027-01-06",
	]
	violation := {{
		"code": "schedule.date_restriction",
		"msg": "2026-12-25 is a disallowed date: 2026-12-25, from:2026-12-19 to:2026-12-31, from:2026-12-20 to:2027-01-06",
	}}

	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as date_rule_data(dates)
		with data.config.policy.when_ns as _rfc_time_helper("2026-12-25")
}

test_date_restriction_leap_day if {
	violation := {{
		"code": "schedule.date_restriction",
		"msg": "2024-02-29 is a disallowed date: 2024-02-29",
	}}

	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as date_rule_data(["2024-02-29"])
		with data.config.policy.when_ns as _rfc_time_helper("2024-02-29")
}

test_rule_data_format_disallowed_date_ranges if {
	invalid_dates := [
		"from:2026-12-19 to:2026-12-19",
		"from:2026-12-31 to:2026-12-19",
		"from:2026-12-19",
		"from:2026-12-19 to:2026-12-31 junk",
		"2026-12-19..2026-12-31",
		"2026-1-01",
		"2026-02-30",
		"2023-02-29",
		"from:2026-02-30 to:2026-03-01",
		"from: 2026-12-19 to:2026-12-31",
		"from:2026-12-19  to:2026-12-31",
		"FROM:2026-12-19 TO:2026-12-31",
	]
	expected := {
	{
		"code": "schedule.rule_data_provided",
		"msg": sprintf("Rule data disallowed_dates has unexpected format: %d: Invalid date %q", [index, date]),
		"severity": "failure",
	} |
		some index, date in invalid_dates
	}

	assertions.assert_equal_results(schedule.deny, _with_v2_twins(expected)) with data.rule_data as {"disallowed_dates": invalid_dates}
		with data.config.policy.when_ns as sunday
}

test_date_restriction_wildcard_single if {
	specification := "*-12-31"
	d := date_rule_data([specification])

	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-12-30")

	assertions.assert_equal_results(schedule.deny, _date_violation("2042-12-31", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-12-31")
	assertions.assert_equal_results(schedule.deny, _date_violation("2043-12-31", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2043-12-31")
}

test_date_restriction_wildcard_range_boundaries if {
	specification := "from:*-07-02 to:*-07-04"
	d := date_rule_data([specification])

	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-07-01")
	assertions.assert_equal_results(schedule.deny, _date_violation("2042-07-02", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-07-02")
	assertions.assert_equal_results(schedule.deny, _date_violation("2042-07-03", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-07-03")
	assertions.assert_equal_results(schedule.deny, _date_violation("2042-07-04", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-07-04")
	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-07-05")
}

test_date_restriction_wildcard_wrapping_range_boundaries if {
	specification := "from:*-12-20 to:*-01-06"
	d := date_rule_data([specification])

	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2041-12-19")
	assertions.assert_equal_results(schedule.deny, _date_violation("2041-12-20", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2041-12-20")
	assertions.assert_equal_results(schedule.deny, _date_violation("2041-12-25", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2041-12-25")
	assertions.assert_equal_results(schedule.deny, _date_violation("2042-01-03", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-01-03")
	assertions.assert_equal_results(schedule.deny, _date_violation("2042-01-06", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-01-06")
	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-01-07")
	assertions.assert_equal_results(schedule.deny, _date_violation("2042-12-20", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-12-20")
	assertions.assert_equal_results(schedule.deny, _date_violation("2043-01-03", [specification])) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2043-01-03")
}

test_date_restriction_jira_wildcard_examples if {
	summer_specification := "from:*-07-02 to:*-07-04"

	assertions.assert_equal_results(schedule.deny, _date_violation("2026-07-03", [summer_specification])) with data.rule_data as date_rule_data([summer_specification])
		with data.config.policy.when_ns as _rfc_time_helper("2026-07-03")

	winter_specification := "from:*-12-20 to:*-01-06"
	assertions.assert_equal_results(schedule.deny, _date_violation("2027-01-03", [winter_specification])) with data.rule_data as date_rule_data([winter_specification])
		with data.config.policy.when_ns as _rfc_time_helper("2027-01-03")
}

test_date_restriction_wildcard_utc_date if {
	specification := "*-12-31"
	d := date_rule_data([specification])
	violation := _date_violation("2026-12-31", [specification])

	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as d
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2026-12-31T00:00:00Z")
	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as d
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2026-12-31T23:59:59Z")
	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as d
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2027-01-01T00:30:00+02:00")
	assertions.assert_empty(schedule.deny) with data.rule_data as d
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2026-12-31T23:30:00-02:00")
}

test_date_restriction_wildcard_pipeline_intention if {
	specification := "*-12-31"
	d := date_rule_data([specification])
	violation := _date_violation("2042-12-31", [specification])
	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as d
		with data.config.policy.when_ns as _rfc_time_helper("2042-12-31")
	production_data := object.union(d, {"pipeline_intention": "production"})
	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as production_data
		with data.config.policy.when_ns as _rfc_time_helper("2042-12-31")

	range_specification := "from:*-12-30 to:*-01-02"
	range_data := object.union(date_rule_data([range_specification]), {"pipeline_intention": "production"})
	assertions.assert_equal_results(schedule.deny, _date_violation("2042-01-01", [range_specification])) with data.rule_data as range_data
		with data.config.policy.when_ns as _rfc_time_helper("2042-01-01")

	build_data := object.union(d, {"pipeline_intention": "build"})
	assertions.assert_empty(schedule.deny) with data.rule_data as build_data
		with data.config.policy.when_ns as _rfc_time_helper("2042-12-31")
	assertions.assert_empty(schedule.deny) with data.rule_data as {"disallowed_dates": [specification]}
		with data.config.policy.when_ns as _rfc_time_helper("2042-12-31")
}

test_date_restriction_overlapping_wildcards if {
	specifications := [
		"*-07-03",
		"from:*-07-02 to:*-07-04",
		"from:*-07-03 to:*-07-05",
	]

	assertions.assert_equal_results(schedule.deny, _date_violation("2042-07-03", specifications)) with data.rule_data as date_rule_data(specifications)
		with data.config.policy.when_ns as _rfc_time_helper("2042-07-03")
}

test_wildcard_date_spec_helpers if {
	schedule._valid_date_spec("*-12-31")
	schedule._valid_date_spec("from:*-07-02 to:*-07-04")
	schedule._valid_date_spec("from:*-12-20 to:*-01-06")
	not schedule._valid_date_spec("2026-*-31")
	not schedule._valid_date_spec("*-13-01")
	not schedule._valid_date_spec("*-02-29")
	not schedule._valid_date_spec("from:*-12-20 to:2027-01-06")
	not schedule._valid_date_spec("from:2026-12-20 to:*-01-06")
	not schedule._valid_date_spec("from:*-07-02 to:*-07-02")

	schedule._date_spec_matches("*-12-31", "2042-12-31")
	schedule._date_spec_matches("from:*-07-02 to:*-07-04", "2042-07-03")
	schedule._date_spec_matches("from:*-12-20 to:*-01-06", "2042-01-03")
	not schedule._date_spec_matches("from:*-12-20 to:*-01-06", "2042-06-01")
}

test_rule_data_format_wildcards if {
	invalid_dates := [
		"",
		"*-13-01",
		"*-00-01",
		"*-04-31",
		"*-02-29",
		"2026-*-31",
		"2026-12-*",
		"from:*-07-02 to:*-07-02",
		"from:*-02-28 to:*-02-29",
		"from:*-02-29 to:*-03-01",
		"from:*-12-20 to:2027-01-06",
		"from:2026-12-20 to:*-01-06",
		"from:*-12-20",
		"from:*-12-20 to:*-01-06 trailing",
		"from:*-12-20  to:*-01-06",
		" from:*-12-20 to:*-01-06",
		"from:*-12-20 to:*-01-06 ",
		"FROM:*-12-20 TO:*-01-06",
		"to:*-01-06 from:*-12-20",
		"from: *-12-20 to: *-01-06",
	]
	expected := {
	{
		"code": "schedule.rule_data_provided",
		"msg": sprintf("Rule data disallowed_dates has unexpected format: %d: Invalid date %q", [index, date]),
		"severity": "failure",
	} |
		some index, date in invalid_dates
	}

	assertions.assert_equal_results(schedule.deny, _with_v2_twins(expected)) with data.rule_data as {"disallowed_dates": invalid_dates}
		with data.config.policy.when_ns as sunday
}

test_pipeline_intention if {
	# With pipeline intention set to "release" we get a violation
	release_weekday_data := weekday_rule_data(["monday"])
	monday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "monday is a disallowed weekday: monday",
	}}
	assertions.assert_equal_results(schedule.deny, monday_violation) with data.rule_data as release_weekday_data
		with data.config.policy.when_ns as monday

	release_date_data := date_rule_data(["2024-05-12"])
	rfc_date := time.parse_rfc3339_ns("2024-05-12T00:00:00Z")
	violation := {{
		"code": "schedule.date_restriction",
		"msg": "2024-05-12 is a disallowed date: 2024-05-12",
	}}
	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as release_date_data
		with data.config.policy.when_ns as rfc_date

	# Without pipeline intention set to "release" we do not get a violation
	build_weekday_data := object.union(release_weekday_data, {"pipeline_intention": null})
	assertions.assert_empty(schedule.deny) with data.rule_data as build_weekday_data
		with data.config.policy.when_ns as monday

	spam_weekday_data := object.union(release_weekday_data, {"pipeline_intention": "spam"})
	assertions.assert_empty(schedule.deny) with data.rule_data as spam_weekday_data
		with data.config.policy.when_ns as monday

	build_date_data := object.union(release_date_data, {"pipeline_intention": null})
	assertions.assert_empty(schedule.deny) with data.rule_data as build_date_data
		with data.config.policy.when_ns as rfc_date

	spam_date_data := object.union(release_date_data, {"pipeline_intention": "spam"})
	assertions.assert_empty(schedule.deny) with data.rule_data as spam_date_data
		with data.config.policy.when_ns as rfc_date
}

test_rule_data_format_disallowed_weekdays if {
	d := {"disallowed_weekdays": [
		# Wrong type
		1,
		# Duplicated items
		"monday",
		"monday",
		# Unsupported mixed case
		"mOnDaY",
	]}

	expected := {
		{
			"code": "schedule.rule_data_provided",
			# regal ignore:line-length
			"msg": `Rule data disallowed_weekdays has unexpected format: 0: 0 must be one of the following: "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"`,
			"severity": "failure",
		},
		{
			"code": "schedule.rule_data_provided",
			"msg": "Rule data disallowed_weekdays has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "schedule.rule_data_provided",
			# regal ignore:line-length
			"msg": `Rule data disallowed_weekdays has unexpected format: 3: 3 must be one of the following: "Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"`,
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(schedule.deny, _with_v2_twins(expected)) with data.rule_data as d
		with data.config.policy.when_ns as sunday
}

test_rule_data_format_disallowed_dates if {
	d := {"disallowed_dates": [
		# Wrong type
		1,
		# Duplicated items
		"2023-01-01",
		"2023-01-01",
		# Not enough digits
		"23-01-01",
		"2023-1-01",
		"2023-01-1",
	]}

	expected := {
		{
			"code": "schedule.rule_data_provided",
			"msg": "Rule data disallowed_dates has unexpected format: 0: Invalid date '\\x01'",
			"severity": "failure",
		},
		{
			"code": "schedule.rule_data_provided",
			"msg": "Rule data disallowed_dates has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "schedule.rule_data_provided",
			"msg": "Rule data disallowed_dates has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "schedule.rule_data_provided",
			"msg": `Rule data disallowed_dates has unexpected format: 3: Invalid date "23-01-01"`,
			"severity": "failure",
		},
		{
			"code": "schedule.rule_data_provided",
			"msg": `Rule data disallowed_dates has unexpected format: 4: Invalid date "2023-1-01"`,
			"severity": "failure",
		},
		{
			"code": "schedule.rule_data_provided",
			"msg": `Rule data disallowed_dates has unexpected format: 5: Invalid date "2023-01-1"`,
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(schedule.deny, _with_v2_twins(expected)) with data.rule_data as d
		with data.config.policy.when_ns as sunday
}

test_rule_data_format_disallowed_dates_root_types if {
	assertions.assert_not_empty(schedule.deny) with data.rule_data as {"disallowed_dates": "2026-12-31"}
		with data.config.policy.when_ns as sunday
	assertions.assert_not_empty(schedule.deny) with data.rule_data as {"disallowed_dates": 1}
		with data.config.policy.when_ns as sunday
	assertions.assert_not_empty(schedule.deny) with data.rule_data as {"disallowed_dates": true}
		with data.config.policy.when_ns as sunday
	assertions.assert_not_empty(schedule.deny) with data.rule_data as {"disallowed_dates": null}
		with data.config.policy.when_ns as sunday

	invalid_object_data := {
		"pipeline_intention": "release",
		"disallowed_dates": {"date": "2026-12-31"},
	}
	expected_object_error := _with_v2_twins({{
		"code": "schedule.rule_data_provided",
		"msg": "Rule data disallowed_dates has unexpected format: (Root): Invalid type. Expected: array, given: object",
		"severity": "failure",
	}})
	assertions.assert_equal_results(schedule.deny, expected_object_error) with data.rule_data as invalid_object_data
		with data.config.policy.when_ns as _rfc_time_helper("2026-12-31")
}

# RA22-SCHEDULE-RULE-DATA-SCALAR-001: a present but scalar `disallowed_weekdays`
# value must produce a format rejection from the v2 rule instead of silently
# skipping the check. The legacy rule_data_provided is untouched: a builtin
# error in its schema validation still suppresses its result, which is the gap
# rule_data_provided_v2 closes. The audit control uses a "release" pipeline
# intention and a fixed Monday evaluation time.
test_rule_data_provided_v2_weekdays_scalar_rejected if {
	expected_integer := {{
		"code": "schedule.rule_data_provided_v2",
		"msg": "Rule data disallowed_weekdays has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(schedule.deny, expected_integer) with data.rule_data as weekday_rule_data(1)
		with data.config.policy.when_ns as monday

	expected_boolean := {{
		"code": "schedule.rule_data_provided_v2",
		"msg": "Rule data disallowed_weekdays has unexpected format: (Root): Invalid type. Expected: array, given: boolean",
		"severity": "failure",
	}}
	assertions.assert_equal_results(schedule.deny, expected_boolean) with data.rule_data as weekday_rule_data(true)
		with data.config.policy.when_ns as monday

	# A string value is malformed even when it contains JSON text for a valid
	# array: JSON text in a scalar must not be mistaken for a native array.
	expected_string := {{
		"code": "schedule.rule_data_provided_v2",
		"msg": "Rule data disallowed_weekdays has unexpected format: (Root): Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(schedule.deny, expected_string) with data.rule_data as weekday_rule_data("x")
		with data.config.policy.when_ns as monday
	assertions.assert_equal_results(schedule.deny, expected_string) with data.rule_data as weekday_rule_data("[]")
		with data.config.policy.when_ns as monday
}

# Unlike `disallowed_weekdays`, the legacy rule already marshals `disallowed_dates`
# scalars before schema validation (see _schema_document), so a scalar value is
# rejected by both rules with the same message; only the code differs.
test_rule_data_provided_v2_dates_scalar_rejected if {
	expected := _with_v2_twins({{
		"code": "schedule.rule_data_provided",
		"msg": "Rule data disallowed_dates has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}})
	assertions.assert_equal_results(schedule.deny, expected) with data.rule_data as date_rule_data(1)
		with data.config.policy.when_ns as monday
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_rule_data_provided_v2_precedence if {
	expected := {{
		"code": "schedule.rule_data_provided_v2",
		"msg": "Rule data disallowed_weekdays has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(schedule.deny, expected) with data.rule_data_custom as weekday_rule_data(1)
		with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as monday
}

# Valid rule data still reaches the weekday restriction consumer: a matching
# list denies, and a nonmatching, explicitly empty, or absent list does not.
test_rule_data_provided_v2_valid_data_reaches_consumers if {
	violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "monday is a disallowed weekday: monday",
	}}
	assertions.assert_equal_results(schedule.deny, violation) with data.rule_data as weekday_rule_data(["monday"])
		with data.config.policy.when_ns as monday

	assertions.assert_empty(schedule.deny) with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as monday

	# An explicit empty list is schema-valid and intentionally disables the restriction.
	assertions.assert_empty(schedule.deny) with data.rule_data as weekday_rule_data([])
		with data.config.policy.when_ns as monday

	# Absent keys fall back to empty data with no format errors.
	assertions.assert_empty(schedule.deny) with data.rule_data as {"pipeline_intention": "release"}
		with data.config.policy.when_ns as monday
}

# Shape controls locking in the current behavior for the remaining root types:
# null and wrong-container values are rejected by both rules.
test_rule_data_provided_v2_root_type_shapes if {
	expected_null := _with_v2_twins({{
		"code": "schedule.rule_data_provided",
		"msg": "Rule data disallowed_weekdays has unexpected format: Provided empty document for schema validation",
		"severity": "failure",
	}})
	assertions.assert_equal_results(schedule.deny, expected_null) with data.rule_data as weekday_rule_data(null)
		with data.config.policy.when_ns as monday

	expected_object := _with_v2_twins({{
		"code": "schedule.rule_data_provided",
		"msg": "Rule data disallowed_weekdays has unexpected format: (Root): Invalid type. Expected: array, given: object",
		"severity": "failure",
	}})
	assertions.assert_equal_results(schedule.deny, expected_object) with data.rule_data as weekday_rule_data({})
		with data.config.policy.when_ns as monday
}

_date_violation(date, specifications) := {{
	"code": "schedule.date_restriction",
	"msg": sprintf("%s is a disallowed date: %s", [date, concat(", ", specifications)]),
}}

# Container-level format issues fire on both the legacy and v2 rules with
# identical messages; only the code differs by the "_v2" suffix.
_with_v2_twins(results) := twins if {
	v2 := {object.union(r, {"code": sprintf("%s_v2", [r.code])}) | some r in results}
	twins := results | v2
}

sunday := _rfc_time_helper("2023-01-01")

monday := _rfc_time_helper("2023-01-02")

tuesday := _rfc_time_helper("2023-01-03")

wednesday := _rfc_time_helper("2023-01-04")

thursday := _rfc_time_helper("2023-01-05")

friday := _rfc_time_helper("2023-01-06")

saturday := _rfc_time_helper("2023-01-07")

_rfc_time_helper(date_string) := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [date_string]))

weekday_rule_data(disallowed_weekdays) := _rule_data_helper("disallowed_weekdays", disallowed_weekdays, "release")

date_rule_data(disallowed_dates) := _rule_data_helper("disallowed_dates", disallowed_dates, "release")

_rule_data_helper(disallowed_key, disallowed_values, pipeline_intention) := {
	"pipeline_intention": pipeline_intention,
	disallowed_key: disallowed_values,
}
