package schedule_test

import rego.v1

import data.lib
import data.schedule

test_no_restriction_by_default if {
	lib.assert_empty(schedule.deny)
}

test_weekday_restriction if {
	_rule_data := weekday_rule_data(["friday", "saturday", "sunday"])

	lib.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as monday

	lib.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as tuesday

	lib.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as wednesday

	lib.assert_empty(schedule.deny) with data.rule_data as _rule_data
		with data.config.policy.when_ns as thursday

	friday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "friday is a disallowed weekday: friday, saturday, sunday",
	}}
	lib.assert_equal_results(schedule.deny, friday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as friday

	saturday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "saturday is a disallowed weekday: friday, saturday, sunday",
	}}
	lib.assert_equal_results(schedule.deny, saturday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as saturday

	sunday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "sunday is a disallowed weekday: friday, saturday, sunday",
	}}
	lib.assert_equal_results(schedule.deny, sunday_violation) with data.rule_data as _rule_data
		with data.config.policy.when_ns as sunday
}

test_weekday_restriction_case_insensitive if {
	violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "friday is a disallowed weekday: friday",
	}}

	lib.assert_equal_results(schedule.deny, violation) with data.rule_data as weekday_rule_data(["FRIDAY"])
		with data.config.policy.when_ns as friday
	lib.assert_empty(schedule.deny) with data.rule_data as weekday_rule_data(["FRIDAY"])
		with data.config.policy.when_ns as monday

	lib.assert_equal_results(schedule.deny, violation) with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as friday
	lib.assert_empty(schedule.deny) with data.rule_data as weekday_rule_data(["friday"])
		with data.config.policy.when_ns as monday
}

test_date_restriction if {
	violation := {{
		"code": "schedule.date_restriction",
		"msg": "2023-01-01 is a disallowed date: 2023-01-01",
	}}
	lib.assert_equal_results(schedule.deny, violation) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-01-01T00:00:00Z")

	lib.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-01-02T00:00:00Z")
	lib.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2023-02-01T00:00:00Z")
	lib.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2024-01-01T00:00:00Z")
	lib.assert_empty(schedule.deny) with data.rule_data as date_rule_data(["2023-01-01"])
		with data.config.policy.when_ns as time.parse_rfc3339_ns("2024-02-03T00:00:00Z")
}

test_schedule_restriction if {
	release_weekday_data := weekday_rule_data(["monday"])
	monday_violation := {{
		"code": "schedule.weekday_restriction",
		"msg": "monday is a disallowed weekday: monday",
	}}
	lib.assert_equal_results(schedule.deny, monday_violation) with data.rule_data as release_weekday_data
		with data.config.policy.when_ns as monday

	release_date_data := date_rule_data(["2024-05-12"])
	rfc_date := time.parse_rfc3339_ns("2024-05-12T00:00:00Z")
	violation := {{
		"code": "schedule.date_restriction",
		"msg": "2024-05-12 is a disallowed date: 2024-05-12",
	}}
	lib.assert_equal_results(schedule.deny, violation) with data.rule_data as release_date_data
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

	lib.assert_equal_results(schedule.deny, expected) with data.rule_data as d
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

	lib.assert_equal_results(schedule.deny, expected) with data.rule_data as d
		with data.config.policy.when_ns as sunday
}

sunday := _rfc_time_helper("2023-01-01")

monday := _rfc_time_helper("2023-01-02")

tuesday := _rfc_time_helper("2023-01-03")

wednesday := _rfc_time_helper("2023-01-04")

thursday := _rfc_time_helper("2023-01-05")

friday := _rfc_time_helper("2023-01-06")

saturday := _rfc_time_helper("2023-01-07")

_rfc_time_helper(date_string) := time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [date_string]))

weekday_rule_data(disallowed_weekdays) := _rule_data_helper("disallowed_weekdays", disallowed_weekdays)

date_rule_data(disallowed_dates) := _rule_data_helper("disallowed_dates", disallowed_dates)

_rule_data_helper(disallowed_key, disallowed_values) := {disallowed_key: disallowed_values}
