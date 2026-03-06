package lib.json_test

import data.lib
import data.lib.assertions
import data.lib.json as j
import rego.v1

test_validate_args if {
	assertions.assert_equal(
		[
			{
				"message": "Provided empty document for schema validation",
				"severity": "failure",
			},
			{
				"message": "Provided empty schema for schema validation",
				"severity": "failure",
			},
		],
		j.validate_schema(null, null),
	)
	assertions.assert_equal(
		[{
			"message": "Provided empty schema for schema validation",
			"severity": "failure",
		}],
		j.validate_schema({}, null),
	)
	assertions.assert_equal(
		[{
			"message": "Provided empty document for schema validation",
			"severity": "failure",
		}],
		j.validate_schema(null, {}),
	)
	assertions.assert_equal(
		[{
			"message": "Provided schema is not a valid JSON Schema: jsonschema: wrong type, expected string or object",
			"severity": "failure",
		}],
		j.validate_schema({}, ["something"]),
	)
}

test_validate_schema_ok if {
	assertions.assert_equal(
		[],
		j.validate_schema({"a": 3}, {
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"properties": {"a": {"type": "number"}},
		}),
	)
	assertions.assert_equal(
		[],
		j.validate_schema([{"a": 3}], {
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "array",
			"items": {"properties": {"a": {"type": "number"}}},
		}),
	)
}

test_validate_schema_not_ok if {
	assertions.assert_equal(
		[{
			"message": "a: Invalid type. Expected: number, given: string",
			"severity": "failure",
		}],
		j.validate_schema({"a": "b"}, {
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"properties": {"a": {"type": "number"}},
		}),
	)
	assertions.assert_equal(
		[{
			"message": "0.a: Invalid type. Expected: number, given: string",
			"severity": "failure",
		}],
		j.validate_schema([{"a": "b"}], {
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"type": "array",
			"items": {"properties": {"a": {"type": "number"}}},
		}),
	)
}

test_validate_schema_unknown_property_warning if {
	assertions.assert_equal(
		[{
			"message": "(Root): Additional property b is not allowed",
			"severity": "warning",
		}],
		j.validate_schema({"a": 3, "b": "here"}, {
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"properties": {"a": {"type": "number"}},
			"additionalProperties": false,
		}),
	)
}
