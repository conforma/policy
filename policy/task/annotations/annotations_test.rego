package annotations_test

import rego.v1

import data.annotations
import data.lib

test_valid_expiry_dates if {
	lib.assert_empty(annotations.deny) with input.metadata.annotations as {annotations._expires_on_annotation: "2000-01-02T03:04:05Z"}
}

test_invalid_expiry_dates if {
	lib.assert_equal_results(annotations.deny, {{
		"code": "annotations.expires_on_format",
		"msg": `Expires on time is not in RFC3339 format: "meh"`,
	}}) with input.metadata.annotations as {annotations._expires_on_annotation: "meh"}
}
