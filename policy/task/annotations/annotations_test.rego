package annotations_test

import rego.v1

import data.lib.assertions

import data.annotations

test_valid_expiry_dates if {
	# regal ignore:line-length
	assertions.assert_empty(annotations.deny) with input as _task({annotations._expires_on_annotation: "2000-01-02T03:04:05Z"})
}

test_invalid_expiry_dates if {
	assertions.assert_equal_results(annotations.deny, {{
		"code": "annotations.expires_on_format",
		"msg": `Expires on time is not in RFC3339 format: "meh"`,
	}}) with input as _task({annotations._expires_on_annotation: "meh"})
}

_task(annots) := {"apiVersion": "tekton.dev/v1", "kind": "Task", "metadata": {"annotations": annots}}
