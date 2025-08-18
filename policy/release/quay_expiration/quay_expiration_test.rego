package quay_expiration_test

import rego.v1

import data.lib
import data.quay_expiration

test_quay_expiration if {
	lib.assert_empty(quay_expiration.deny) with input.image as _image_expires_none

	expected := {{
		"code": "quay_expiration.expires_label",
		"msg": "The label 'quay.expires-after' is not allowed",
	}}

	lib.assert_equal_results(expected, quay_expiration.deny) with input.image as _image_expires_blank

	lib.assert_equal_results(expected, quay_expiration.deny) with input.image as _image_expires_5d
}

_image_expires_5d := {"config": {"Labels": {
	"foo": "bar",
	"quay.expires-after": "5d",
}}}

_image_expires_blank := {"config": {"Labels": {
	"foo": "bar",
	"quay.expires-after": "",
}}}

_image_expires_none := {"config": {"Labels": {"foo": "bar"}}}
