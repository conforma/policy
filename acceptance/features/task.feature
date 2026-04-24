Feature: Task Definition

    Scenario: Successful Red Hat collection
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
                            "$GITROOT/example/data"
                        ],
                        "config": {
                            "include": [
                                "results.*"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be no violations in the result
        Then there should be no warnings in the result

    Scenario: Trusted task using trusted_task_rules
        Given a sample policy input "trusted-task"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/pipeline"
                        ],
                        "data": [
                            "$GITROOT/example/data",
                            "$GITROOT/acceptance/testdata/trusted-task-rules"
                        ],
                        "config": {
                            "include": [
                                "task_bundle.*"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be no violations in the result

    Scenario: Untrusted task rejected by trusted_task_rules
        Given a sample policy input "untrusted-task"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/pipeline"
                        ],
                        "data": [
                            "$GITROOT/example/data",
                            "$GITROOT/acceptance/testdata/trusted-task-rules"
                        ],
                        "config": {
                            "include": [
                                "task_bundle.*"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be violations in the result

    Scenario: Task rejected by trusted_task_rules because of no tag in the manifest annotations (tag in oci ref is ignored)
        Given a sample policy input "untrusted-task-despite-valid-oci-ref-tag"
        And a policy config:
            """
            {
                "sources": [
                    {
                        "policy": [
                            "$GITROOT/policy/lib",
                            "$GITROOT/policy/pipeline"
                        ],
                        "data": [
                            "$GITROOT/example/data",
                            "$GITROOT/acceptance/testdata/trusted-task-rules"
                        ],
                        "config": {
                            "include": [
                                "task_bundle.*"
                            ]
                        }
                    }
                ]
            }
            """
        When input is validated
        Then there should be violations in the result
