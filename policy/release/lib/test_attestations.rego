package lib

import rego.v1

import data.lib.time as lib_time

# The integration-test identity defined by the in-toto test-result predicate.
attestation_test_name(statement) := name if {
	predicate := object.get(statement, "predicate", {})
	config := object.get(predicate, "configuration", [])
	count(config) > 0
	name := config[0].name
	is_string(name)
	name != ""
}

# The instant represented by a test-result timestamp. Statements with a
# missing, empty, or invalid RFC 3339 timestamp are not latest-run candidates.
attestation_test_instant(statement) := instant if {
	timestamp := statement.predicate.timestamp
	is_string(timestamp)
	instant := lib_time.parse_rfc3339_safe(timestamp)
}

# Keep the statement with the greatest timestamp for each integration-test
# name. If statements tie for the greatest timestamp, retain every tied value.
latest_test_attestations(statements) := {statement |
	some test_name in {attestation_test_name(candidate) | some candidate in statements}
	test_runs := {candidate |
		some candidate in statements
		attestation_test_name(candidate) == test_name
	}
	latest_instant := max({attestation_test_instant(candidate) | some candidate in test_runs})

	some statement in test_runs
	attestation_test_instant(statement) == latest_instant
}
