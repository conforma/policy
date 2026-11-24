Feature: Rule data format rules

    Scenario: Scalar required_labels rule data is rejected by the v2 rule in the Red Hat collection
        Given a sample policy input "golden-container"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/release"
                        ],
                        "data": [
                            "$GITROOT/acceptance/testdata/rule-data-format-labels"
                        ],
                        "config": {
                            "include": [
                                "@redhat"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2027-01-12T00:00:00Z"
        When input is validated
        Then there should be violations with "labels.rule_data_provided_v2" code in the result
        And there should be no violations with "labels.rule_data_provided" code in the result

    Scenario: The labels v2 format rule does not fire before its effective date
        Given a sample policy input "golden-container"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/release"
                        ],
                        "data": [
                            "$GITROOT/acceptance/testdata/rule-data-format-labels"
                        ],
                        "config": {
                            "include": [
                                "@redhat"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2027-01-01T00:00:00Z"
        When input is validated
        Then there should be no violations with "labels.rule_data_provided_v2" code in the result
        And there should be no violations with "labels.rule_data_provided" code in the result

    Scenario: Scalar disallowed_packages rule data is rejected by the v2 rule in the policy_data collection
        Given a sample policy input "golden-container"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/release"
                        ],
                        "data": [
                            "$GITROOT/acceptance/testdata/rule-data-format-sbom"
                        ],
                        "config": {
                            "include": [
                                "@policy_data"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2027-01-12T00:00:00Z"
        When input is validated
        Then there should be violations with "sbom.disallowed_packages_provided_v2" code in the result
        And there should be no violations with "sbom.disallowed_packages_provided" code in the result

    Scenario: Scalar required_task_results rule data is rejected by the explicitly selected v2 rule
        Given a sample policy input "clamav-task"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/task"
                        ],
                        "data": [
                            "$GITROOT/acceptance/testdata/rule-data-format-results"
                        ],
                        "config": {
                            "include": [
                                "results.rule_data_provided_v2"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2027-01-12T00:00:00Z"
        When input is validated
        Then there should be violations with "results.rule_data_provided_v2" code in the result
        And there should be no violations with "results.rule_data_provided" code in the result
