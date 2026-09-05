Feature: Trusted tasks in Integration Test Service PipelineRuns

    Background:
        Given a policy config:
            """
            {
                "publicKey": $ITS_PUBLIC_KEY,
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/release"
                        ],
                        "data": [
                            "$GITROOT/acceptance/testdata/its-trusted-tasks"
                        ],
                        "config": {
                            "include": [
                                "tasks.required_test_tasks_found",
                                "tasks.required_untrusted_test_task_found"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-10-02T00:00:00Z"

    Scenario: A required test task is trusted when every task in its SLSA v1 provenance is trusted
        Given a sample policy input "its-fully-trusted"
        When input is validated
        Then there should be no violations with "tasks.required_test_tasks_found" code in the result
        And there should be no violations with "tasks.required_untrusted_test_task_found" code in the result

    Scenario: An explicitly denied helper task makes the required test task untrusted
        Given a sample policy input "its-untrusted-helper"
        When input is validated
        Then there should be a violation with "tasks.required_untrusted_test_task_found" code, "prepare-test" term, and a message containing "in its provenance is untrusted"

    Scenario: A bundleless helper task fails closed
        Given a sample policy input "its-unknown-helper"
        When input is validated
        Then there should be a violation with "tasks.required_untrusted_test_task_found" code, "unknown-helper" term, and a message containing "in its provenance is untrusted"

    Scenario: A test result without SLSA provenance does not satisfy the required test task
        Given a sample policy input "its-missing-provenance"
        When input is validated
        Then there should be a violation with "tasks.required_test_tasks_found" code, "clair-scan" term, and a message containing "is missing"

    Scenario: A test result with malformed SLSA v1 provenance does not satisfy the required test task
        Given a sample policy input "its-malformed-provenance"
        When input is validated
        Then there should be a violation with "tasks.required_test_tasks_found" code, "clair-scan" term, and a message containing "is missing"

    Scenario: Only the latest retry of each integration test is considered
        Given a sample policy input "its-latest-retry-trusted"
        When input is validated
        Then there should be no violations with "tasks.required_test_tasks_found" code in the result
        And there should be no violations with "tasks.required_untrusted_test_task_found" code in the result

    Scenario: An untrusted latest retry is not masked by an older trusted run
        Given a sample policy input "its-latest-retry-untrusted"
        When input is validated
        Then there should be a violation with "tasks.required_untrusted_test_task_found" code, "clair-scan" term, and a message containing "in its provenance is untrusted"
