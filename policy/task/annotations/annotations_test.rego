package annotations_test

import rego.v1

import data.lib.assertions

import data.annotations

test_valid_expiry_dates if {
	# regal ignore:line-length
	assertions.assert_empty(annotations.deny) with input.metadata.annotations as {annotations._expires_on_annotation: "2000-01-02T03:04:05Z"}
}

test_invalid_expiry_dates if {
	assertions.assert_equal_results(annotations.deny, {{
		"code": "annotations.expires_on_format",
		"msg": `Expires on time is not in RFC3339 format: "meh"`,
	}}) with input.metadata.annotations as {annotations._expires_on_annotation: "meh"}
}
