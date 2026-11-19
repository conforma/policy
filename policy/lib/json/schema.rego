package lib.json

import rego.v1

# Validates schema reporting the error message as well as the severity
validate_schema(doc, schema) := issues if {
	count(_arg_issues(doc, schema)) == 0
	issues := _validation_issues(doc, schema)
} else := _arg_issues(doc, schema)

# Validates a native Rego value against the schema, reporting issues in the same
# shape as validate_schema. Unlike validate_schema, the document is always
# marshaled and passed to json.match_schema as JSON text, so a scalar document
# (a number, boolean or string) is reported as a schema violation instead of
# raising a builtin error that suppresses the result, and a string is never
# interpreted as serialized JSON. Use this for values that are native rule data
# rather than JSON documents; keep validate_schema for documents that may
# legitimately be serialized JSON, like annotation values.
validate_schema_native(doc, schema) := issues if {
	count(_arg_issues(doc, schema)) == 0
	issues := _validation_issues_native(doc, schema)
} else := _arg_issues(doc, schema)

_validation_issues(doc, schema) := issues if {
	not is_null(doc)
	not is_null(schema)
	d := _prepare_document(doc)
	issues := _match_issues(d, schema)
}

_validation_issues_native(doc, schema) := issues if {
	not is_null(doc)
	not is_null(schema)
	issues := _match_issues(json.marshal(doc), schema)
}

_match_issues(d, schema) := issues if {
	ok_error := json.match_schema(d, schema)
	ok := ok_error[0]
	not ok
	errors := ok_error[1]
	issues := [i |
		some e in errors
		i := {
			"message": e.error, # e.desc is ignored, seems to repeat what is in e.error
			"severity": _severity(e),
		}
	]
}

_arg_issues(doc, schema) := [i |
	some check in [
		{is_null(doc) == false: "Provided empty document for schema validation"},
		{is_null(schema) == false: "Provided empty schema for schema validation"},
		_check_schema(schema),
	]
	some ok, msg in check
	not ok
	i := {
		"message": msg,
		"severity": "failure",
	}
]

_check_schema(schema) := ok_msg if {
	not is_null(schema)
	ok_error := json.verify_schema(schema)
	ok := ok_error[0]
	not ok
	error := ok_error[1]
	ok_msg := {false: sprintf("Provided schema is not a valid JSON Schema: %s", [error])}
} else := {true, ""}

_prepare_document(doc) := d if {
	is_array(doc)

	# match_schema expects either a marshaled JSON resource (String) or an
	# Object. It doesn't handle an Array directly.
	d := json.marshal(doc)
} else := doc

_severity(e) := "warning" if {
	startswith(e.desc, "Additional property")
} else := "failure"
