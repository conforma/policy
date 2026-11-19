package lib.json_test

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
			"message": "Provided schema is not a valid JSON Schema: jsonschema: schema is invalid",
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

test_validate_schema_native_args if {
	# Null documents and schemas are reported the same way as validate_schema.
	assertions.assert_equal(
		[{
			"message": "Provided empty document for schema validation",
			"severity": "failure",
		}],
		j.validate_schema_native(null, {}),
	)
	assertions.assert_equal(
		[{
			"message": "Provided empty schema for schema validation",
			"severity": "failure",
		}],
		j.validate_schema_native([], null),
	)
}

test_validate_schema_native_ok if {
	array_schema := {
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "array",
		"items": {"type": "string"},
		"uniqueItems": true,
	}
	assertions.assert_equal([], j.validate_schema_native(["a", "b"], array_schema))
	assertions.assert_equal([], j.validate_schema_native([], array_schema))
	assertions.assert_equal(
		[],
		j.validate_schema_native({"a": 3}, {
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"properties": {"a": {"type": "number"}},
		}),
	)
}

# A scalar document must be reported as a schema violation instead of raising a
# builtin error that suppresses the result (the gap this helper closes).
test_validate_schema_native_scalar_rejected if {
	array_schema := {
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "array",
		"items": {"type": "string"},
		"uniqueItems": true,
	}
	assertions.assert_equal(
		[{
			"message": "(Root): Invalid type. Expected: array, given: integer",
			"severity": "failure",
		}],
		j.validate_schema_native(3, array_schema),
	)
	assertions.assert_equal(
		[{
			"message": "(Root): Invalid type. Expected: array, given: boolean",
			"severity": "failure",
		}],
		j.validate_schema_native(true, array_schema),
	)
	assertions.assert_equal(
		[{
			"message": "(Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		}],
		j.validate_schema_native("x", array_schema),
	)
	# A string containing JSON text is a native string, not a JSON document:
	# unlike validate_schema it must not be parsed and accepted as an array.
	assertions.assert_equal(
		[{
			"message": "(Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		}],
		j.validate_schema_native("[]", array_schema),
	)
}

# Containers keep the same diagnostics as validate_schema, including nested
# item violations, uniqueness and additional-property warnings.
test_validate_schema_native_container_issues if {
	array_schema := {
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "array",
		"items": {"type": "string"},
		"uniqueItems": true,
	}
	assertions.assert_equal(
		[{
			"message": "(Root): array items[0,1] must be unique",
			"severity": "failure",
		}],
		j.validate_schema_native(["a", "a"], array_schema),
	)
	assertions.assert_equal(
		[{
			"message": "0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		}],
		j.validate_schema_native([3], array_schema),
	)
	assertions.assert_equal(
		[{
			"message": "(Root): Additional property b is not allowed",
			"severity": "warning",
		}],
		j.validate_schema_native({"a": 3, "b": "here"}, {
			"$schema": "https://json-schema.org/draft/2020-12/schema",
			"properties": {"a": {"type": "number"}},
			"additionalProperties": false,
		}),
	)
}

# Compatibility control for the distinction between the two helpers:
# validate_schema interprets a string document as serialized JSON, which
# legitimate callers like the OLM subscription annotation rely on, while
# validate_schema_native treats it as a native string.
test_validate_schema_interprets_json_text if {
	array_schema := {
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "array",
		"items": {"type": "string"},
		"uniqueItems": true,
	}
	assertions.assert_equal([], j.validate_schema(`["a", "b"]`, array_schema))
	assertions.assert_equal(
		[{
			"message": "(Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		}],
		j.validate_schema_native(`["a", "b"]`, array_schema),
	)
}
