package lib_test

import rego.v1

import data.lib
import data.lib.assertions

_test_result_statement(name, timestamp) := {"predicate": {
	"configuration": [{"name": name}],
	"timestamp": timestamp,
}}

test_attestation_test_name_uses_configuration_name if {
	statement := _test_result_statement("integration-1", "2026-01-01T00:00:00Z")
	assertions.assert_equal("integration-1", lib.attestation_test_name(statement))
}

test_attestation_test_name_is_undefined_without_a_nonempty_string_name if {
	not lib.attestation_test_name({"predicate": {}})
	not lib.attestation_test_name({"predicate": {"configuration": []}})
	not lib.attestation_test_name({"predicate": {"configuration": [{}]}})
	not lib.attestation_test_name({"predicate": {"configuration": [{"name": ""}]}})
	not lib.attestation_test_name({"predicate": {"configuration": [{"name": 1}]}})
}

test_attestation_test_instant_requires_a_valid_rfc3339_timestamp if {
	statement := _test_result_statement("integration-1", "2026-01-01T00:00:00Z")
	assertions.assert_equal(time.parse_rfc3339_ns("2026-01-01T00:00:00Z"), lib.attestation_test_instant(statement))
	not lib.attestation_test_instant({"predicate": {}})
	not lib.attestation_test_instant({"predicate": {"timestamp": ""}})
	not lib.attestation_test_instant({"predicate": {"timestamp": 1}})
	not lib.attestation_test_instant({"predicate": {"timestamp": "not-a-date"}})
}

test_latest_test_attestations_keeps_latest_run_per_test if {
	integration_1_old := _test_result_statement("integration-1", "2026-01-01T01:00:00Z")
	integration_1_latest := _test_result_statement("integration-1", "2026-01-01T03:00:00Z")
	integration_2 := _test_result_statement("integration-2", "2026-01-01T02:00:00Z")

	assertions.assert_equal(
		{integration_1_latest, integration_2},
		lib.latest_test_attestations({integration_1_old, integration_1_latest, integration_2}),
	)
}

test_latest_test_attestations_ignores_runs_without_timestamps if {
	without_timestamp := {"predicate": {"configuration": [{"name": "integration-1"}]}}
	assertions.assert_empty(lib.latest_test_attestations({without_timestamp}))
}

test_latest_test_attestations_retains_timestamp_ties if {
	first := object.union(_test_result_statement("integration-1", "2026-01-01T00:00:00Z"), {"id": 1})
	second := object.union(_test_result_statement("integration-1", "2026-01-01T00:00:00Z"), {"id": 2})
	assertions.assert_equal({first, second}, lib.latest_test_attestations({first, second}))
}

test_latest_test_attestations_compares_timestamp_instants if {
	older := _test_result_statement("integration-1", "2026-01-01T01:00:00Z")
	later_with_offset := _test_result_statement("integration-1", "2026-01-01T00:30:00-01:00")
	assertions.assert_equal(
		{later_with_offset},
		lib.latest_test_attestations({older, later_with_offset}),
	)
}

test_latest_test_attestations_ignores_invalid_timestamps if {
	invalid := _test_result_statement("integration-1", "not-a-date")
	assertions.assert_empty(lib.latest_test_attestations({invalid}))
}
