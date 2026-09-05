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

test_attestation_test_timestamp_requires_a_nonempty_string if {
	statement := _test_result_statement("integration-1", "2026-01-01T00:00:00Z")
	assertions.assert_equal("2026-01-01T00:00:00Z", lib.attestation_test_timestamp(statement))
	not lib.attestation_test_timestamp({"predicate": {}})
	not lib.attestation_test_timestamp({"predicate": {"timestamp": ""}})
	not lib.attestation_test_timestamp({"predicate": {"timestamp": 1}})
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
