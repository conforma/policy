package lib

import rego.v1

# The integration-test identity defined by the in-toto test-result predicate.
attestation_test_name(statement) := name if {
	predicate := object.get(statement, "predicate", {})
	config := object.get(predicate, "configuration", [])
	count(config) > 0
	name := config[0].name
	is_string(name)
	name != ""
}

# A timestamp suitable for ordering test-result attestations. Statements with a
# missing or empty timestamp are not candidates when selecting the latest run.
attestation_test_timestamp(statement) := timestamp if {
	timestamp := statement.predicate.timestamp
	is_string(timestamp)
	timestamp != ""
}

# Keep the statement with the greatest timestamp for each integration-test
# name. If statements tie for the greatest timestamp, retain every tied value.
latest_test_attestations(statements) := {statement |
	some test_name in {attestation_test_name(candidate) | some candidate in statements}
	test_runs := {candidate |
		some candidate in statements
		attestation_test_name(candidate) == test_name
	}
	latest_timestamp := max({attestation_test_timestamp(candidate) | some candidate in test_runs})

	some statement in test_runs
	attestation_test_timestamp(statement) == latest_timestamp
}
