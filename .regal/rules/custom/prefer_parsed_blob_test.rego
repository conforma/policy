package custom.regal.rules.custom["prefer-parsed-blob_test"]

import rego.v1

import data.custom.regal.rules.custom["prefer-parsed-blob"] as rule

test_direct_unmarshal_blob_detected if {
	r := rule.report with input as regal.parse_module("test.rego", `
		package test
		import rego.v1
		x := json.unmarshal(ec.oci.blob(ref))
	`)
	count(r) == 1
}

test_two_step_not_detected if {
	r := rule.report with input as regal.parse_module("test.rego", `
		package test
		import rego.v1
		blob := ec.oci.blob(ref)
		x := json.unmarshal(blob)
	`)
	count(r) == 0
}

test_parsed_blob_not_detected if {
	r := rule.report with input as regal.parse_module("test.rego", `
		package test
		import rego.v1
		import data.lib.oci
		x := oci.parsed_blob(ref)
	`)
	count(r) == 0
}

test_unmarshal_other_function_not_detected if {
	r := rule.report with input as regal.parse_module("test.rego", `
		package test
		import rego.v1
		x := json.unmarshal(some_other_function(ref))
	`)
	count(r) == 0
}

test_comment_line_not_detected if {
	r := rule.report with input as regal.parse_module("test.rego", `
		package test
		import rego.v1
		# use oci.parsed_blob instead of json.unmarshal(ec.oci.blob(ref))
		x := oci.parsed_blob(ref)
	`)
	count(r) == 0
}
