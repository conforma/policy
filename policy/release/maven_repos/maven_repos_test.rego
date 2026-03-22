package release.maven_repos_test

import data.lib
import data.lib.sbom
import data.release.maven_repos
import future.keywords.if

mock_data := {"allowed_maven_repositories": [
	"https://repo.maven.apache.org/maven2/",
	"https://repo.clojars.org/",
]}

test_cyclonedx_permitted if {
	cdx_input := {"components": [{
		"purl": "pkg:maven/org.apache/log4j@2.17.1",
		"name": "log4j",
		"externalRefs": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/"}],
	}]}

	lib.assert_empty(maven_repos.deny) with data.rule_data as mock_data
		with lib.cyclonedx.packages as cdx_input.components
}

test_spdx_permitted if {
	spdx_input := {"packages": [{
		"purl": "pkg:maven/com.redhat/example@1.0",
		"name": "example",
		"externalRefs": [{
			"referenceType": "distribution",
			"referenceLocator": "https://repo.clojars.org/",
		}],
	}]}

	lib.assert_empty(maven_repos.deny) with data.rule_data as mock_data
		with lib.spdx.packages as spdx_input.packages
}

test_default_maven_central_pass if {
	cdx_input := {"components": [{
		"purl": "pkg:maven/org.base/no-url@1.0",
		"name": "no-url",
		"externalRefs": [],
	}]}

	lib.assert_empty(maven_repos.deny) with data.rule_data as mock_data
		with lib.cyclonedx.packages as cdx_input
}

test_default_cdx_fail if {
	restricted_data := {"allowed_maven_repositories": ["https://internal.repo/"]}

	mock_cdx := {"components": [{
		"purl": "pkg:maven/org.base/no-url@1.0",
		"name": "no-url",
		"externalRefs": [],
	}]}

	expected := {{
		"code": "release.maven_repos.deny_unpermitted_urls",
		"msg": "Package \"pkg:maven/org.base/no-url@1.0\" (source: \"https://repo.maven.apache.org/maven2/\") is not in the permitted list",
		"effective_on": "2026-05-10T00:00:00Z",
		"term": "pkg:maven/org.base/no-url@1.0",
	}}

	lib.assert_equal(maven_repos.deny, expected) with data.rule_data as restricted_data
		with sbom.cyclonedx_sboms as [mock_cdx]
}

test_spdx_default_fail if {
	mock_spdx := {"packages": [{
		"name": "no-url",
		"purl": "pkg:maven/org.base/no-url@1.0",
		"externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:maven/org.base/no-url@1.0"}],
		"downloadLocation": "NOASSERTION",
	}]}
	result := maven_repos.deny with sbom.spdx_sboms as [mock_spdx]
		with data.rule_data as {"allowed_maven_repositories": ["https://internal.repo/"]}
	count(result) > 0
}

test_missing_rule_data if {
	expected := {{
		"code": "release.maven_repos.policy_data_missing",
		"collections": ["policy_data"],
		"effective_on": "2022-01-01T00:00:00Z",
		"msg": "Policy data is missing the required \"allowed_maven_repositories\" list",
	}}
	lib.assert_equal(maven_repos.deny, expected) with data.rule_data as {}
}

test_get_effective_url_provided if {
	url := "https://repo1.maven.org/maven2/"
	maven_repos._get_effective_url(url) == url
}

test_url_is_permitted_true if {
	mock_allowed := ["https://repo.maven.apache.org/maven2/", "https://internal.repo/"]

	maven_repos._url_is_permitted("https://internal.repo/") with data.rule_data.allowed_maven_repositories as mock_allowed
}

test_url_is_permitted_false if {
	mock_allowed := ["https://internal.repo/"]
	not maven_repos._url_is_permitted("https://repo.maven.apache.org/maven2/") with data.rule_data.allowed_maven_repositories as mock_allowed
}

test_rule_data_errors_when_empty_array if {
	mock_data := {"allowed_maven_repositories": []}

	errors := maven_repos._rule_data_errors with data.rule_data as mock_data

	count(errors) == 1
}

test_cyclonedx_multiple_refs_behavior if {
	mock_cdx := {"components": [{
		"name": "multi-ref-lib",
		"purl": "pkg:maven/org.example/multi@1.0",
		"externalRefs": [
			{"type": "distribution", "url": "https://first.repo.com"},
			{"type": "artifact-repository", "url": "https://second.repo.com"},
		],
	}]}

	pkg_list := sbom.packages with sbom.cyclonedx_sboms as [mock_cdx]

	count(pkg_list) == 2
	urls := {p.repository_url | some p in pkg_list}
	urls == {"https://first.repo.com", "https://second.repo.com"}
}

test_spdx_multiple_refs_behavior if {
	mock_spdx := {"packages": [{
		"name": "multi-ref-spdx",
		"purl": "pkg:maven/org.example/spdx@1.0",
		"externalRefs": [
			{"referenceType": "repository", "referenceLocator": "https://primary.repo.com"},
			{"referenceType": "distribution", "referenceLocator": "https://mirror.repo.com"},
		],
	}]}

	pkg_list := sbom.packages with sbom.spdx_sboms as [mock_spdx]

	count(pkg_list) == 2
	urls := {p.repository_url | some p in pkg_list}
	urls == {"https://primary.repo.com", "https://mirror.repo.com"}
}
