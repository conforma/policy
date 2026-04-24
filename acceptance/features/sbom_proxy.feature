Feature: SBOM proxy rules

    Scenario: SPDX proxy metadata required denies RPM packages missing sourceInfo
        Given a sample policy input "spdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules"
                        ],
                        "config": {
                            "include": [
                                "sbom_spdx.proxy_metadata_required"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-07-01T00:00:00Z"
        When input is validated
        Then there should be violations with "sbom_spdx.proxy_metadata_required" code in the result
        And there should be no violations with "sbom_spdx.proxy_metadata_required" code and "pkg:npm/%40babel/code-frame@7.29.0" term in the result

    Scenario: SPDX proxy metadata required does not fire for non-proxy PURL types
        Given a sample policy input "spdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules-npm-only"
                        ],
                        "config": {
                            "include": [
                                "sbom_spdx.proxy_metadata_required"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-07-01T00:00:00Z"
        When input is validated
        Then there should be no violations in the result

    Scenario: SPDX allowed proxy URLs denies non-matching downloadLocation
        Given a sample policy input "spdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules"
                        ],
                        "config": {
                            "include": [
                                "sbom_spdx.allowed_proxy_urls"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-07-01T00:00:00Z"
        When input is validated
        Then there should be violations with "sbom_spdx.allowed_proxy_urls" code in the result
        And there should be no violations with "sbom_spdx.allowed_proxy_urls" code and "pkg:npm/%40babel/code-frame@7.29.0" term in the result

    Scenario: SPDX proxy rules do not fire before effective date
        Given a sample policy input "spdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules"
                        ],
                        "config": {
                            "include": [
                                "sbom_spdx.proxy_metadata_required",
                                "sbom_spdx.allowed_proxy_urls"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-05-01T00:00:00Z"
        When input is validated
        Then there should be no violations in the result

    Scenario: CycloneDX proxy metadata required denies components missing distribution ref
        Given a sample policy input "cdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules"
                        ],
                        "config": {
                            "include": [
                                "sbom_cyclonedx.proxy_metadata_required"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-07-01T00:00:00Z"
        When input is validated
        Then there should be violations with "sbom_cyclonedx.proxy_metadata_required" code in the result
        And there should be no violations with "sbom_cyclonedx.proxy_metadata_required" code and "pkg:npm/%40babel/code-frame@7.29.0" term in the result

    Scenario: CycloneDX proxy metadata required does not fire for non-proxy PURL types
        Given a sample policy input "cdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules-npm-only"
                        ],
                        "config": {
                            "include": [
                                "sbom_cyclonedx.proxy_metadata_required"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-07-01T00:00:00Z"
        When input is validated
        Then there should be no violations in the result

    Scenario: CycloneDX allowed proxy URLs denies non-matching distribution URL
        Given a sample policy input "cdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules"
                        ],
                        "config": {
                            "include": [
                                "sbom_cyclonedx.allowed_proxy_urls"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-07-01T00:00:00Z"
        When input is validated
        Then there should be violations with "sbom_cyclonedx.allowed_proxy_urls" code in the result
        And there should be no violations with "sbom_cyclonedx.allowed_proxy_urls" code and "pkg:npm/%40babel/code-frame@7.29.0" term in the result

    Scenario: CycloneDX proxy rules do not fire before effective date
        Given a sample policy input "cdx-sbom"
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
                            "$GITROOT/acceptance/testdata/proxy-rules"
                        ],
                        "config": {
                            "include": [
                                "sbom_cyclonedx.proxy_metadata_required",
                                "sbom_cyclonedx.allowed_proxy_urls"
                            ]
                        }
                    }
                ]
            }
            """
        And an effective time of "2026-05-01T00:00:00Z"
        When input is validated
        Then there should be no violations in the result
