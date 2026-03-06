package quay_expiration_test

import rego.v1

import data.lib
import data.lib.assertions
import data.quay_expiration

test_ci_pipeline if {
	assertions.assert_empty(quay_expiration.deny) with input.image as _image_expires_none
		with data.rule_data as _rule_data_for_ci

	assertions.assert_empty(quay_expiration.deny) with input.image as _image_expires_blank
		with data.rule_data as _rule_data_for_ci

	assertions.assert_empty(quay_expiration.deny) with input.image as _image_expires_5d
		with data.rule_data as _rule_data_for_ci
}

test_release_pipeline if {
	assertions.assert_empty(quay_expiration.deny) with input.image as _image_expires_none
		with data.rule_data as _rule_data_for_release

	expected := {{
		"code": "quay_expiration.expires_label",
		"msg": "The label 'quay.expires-after' is not allowed in the released image",
	}}

	assertions.assert_equal_results(expected, quay_expiration.deny) with input.image as _image_expires_blank
		with data.rule_data as _rule_data_for_release

	assertions.assert_equal_results(expected, quay_expiration.deny) with input.image as _image_expires_5d
		with data.rule_data as _rule_data_for_release
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

_rule_data_for_ci := {}

_rule_data_for_release := {"pipeline_intention": "release"}
