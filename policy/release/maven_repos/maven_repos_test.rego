package release.maven_repos

import data.lib
import future.keywords.if

mock_data := {"allowed_maven_repositories": [
	"https://repo.maven.apache.org/maven2/",
	"https://maven.repository.redhat.com/ga/",
]}

test_cyclonedx_permitted if {
	cdx_input := {"components": [{
		"purl": "pkg:maven/org.apache/log4j@2.17.1",
		"name": "log4j",
		"externalRefs": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/"}],
	}]}

	lib.assert_empty(deny) with data.rule_data as mock_data
		with data.lib.cyclonedx.packages as cdx_input.components
}

test_spdx_permitted if {
	spdx_input := {"packages": [{
		"purl": "pkg:maven/com.redhat/example@1.0",
		"name": "example",
		"externalRefs": [{
			"referenceType": "distribution",
			"referenceLocator": "https://maven.repository.redhat.com/ga/",
		}],
	}]}

	lib.assert_empty(deny) with data.rule_data as mock_data
		with data.lib.spdx.packages as spdx_input.packages
}

test_default_maven_central_pass if {
	cdx_input := {"components": [{
		"purl": "pkg:maven/org.base/no-url@1.0",
		"name": "no-url",
		"externalRefs": [],
	}]}

	lib.assert_empty(deny) with data.rule_data as mock_data
		with data.lib.cyclonedx.packages as cdx_input
}

test_default_cdx_fail if {
	restricted_data := {"allowed_maven_repositories": ["https://internal.repo/"]}

	cdx_input := {"components": [{
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

	lib.assert_equal(deny, expected) with data.rule_data as restricted_data
		with data.lib.cyclonedx.packages as cdx_input.components
}

test_spdx_default_fail if {
	spdx_input := {"packages": [{
		"name": "no-url",
		"purl": "pkg:maven/org.base/no-url@1.0",
		"externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:maven/org.base/no-url@1.0"}],
		"downloadLocation": "NOASSERTION",
	}]}
	result := deny with data.lib.spdx.packages as spdx_input.packages
		with data.rule_data as {"allowed_maven_repositories": ["https://internal.repo/"]}
	count(result) > 0
}

test_missing_rule_data if {
	expected := {{
		"code": "release.maven_repos.policy_data_missing",
		"effective_on": "2026-05-10T00:00:00Z",
		"msg": "Policy data is missing the required \"allowed_maven_repositories\" list",
	}}
	lib.assert_equal(deny, expected) with data.rule_data as {}
}

test_get_effective_url_provided if {
	url := "https://repo1.maven.org/maven2/"
	data.release.maven_repos._get_effective_url(url) == url
}

test_url_is_permitted_true if {
	mock_allowed := ["https://repo.maven.apache.org/maven2/", "https://internal.repo/"]

	data.release.maven_repos._url_is_permitted("https://internal.repo/") with data.rule_data.allowed_maven_repositories as mock_allowed
}

test_url_is_permitted_false if {
	mock_allowed := ["https://internal.repo/"]
	not data.release.maven_repos._url_is_permitted("https://repo.maven.apache.org/maven2/") with data.rule_data.allowed_maven_repositories as mock_allowed
}

test_rule_data_errors_when_empty_array if {
	mock_data := {"allowed_maven_repositories": []}

	errors := data.release.maven_repos._rule_data_errors with data.rule_data as mock_data

	count(errors) == 1
}
