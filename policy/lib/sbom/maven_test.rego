package lib.sbom.maven_test

import future.keywords.if
import future.keywords.in

import data.lib.sbom.maven

test_cyclonedx_maven_extraction if {
	mock_cdx := [{"name": "auth-lib", "purl": "pkg:maven/org.example/auth@1.0", "externalRefs": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/"}]}]

	res := maven.packages with data.lib.cyclonedx.packages as mock_cdx

	res == {{
		"name": "auth-lib",
		"purl": "pkg:maven/org.example/auth@1.0",
		"repository_url": "https://repo.maven.apache.org/maven2/",
	}}
}

test_cyclonedx_ignores_non_maven if {
	mock_cdx := [{"name": "react", "purl": "pkg:npm/react@18.2.0"}]
	res := maven.packages with data.lib.cyclonedx.packages as mock_cdx
	count(res) == 0
}

test_cyclonedx_empty_repo_url if {
	mock_cdx := [{"name": "no-repo", "purl": "pkg:maven/org.example/no-repo@1.0", "externalRefs": []}]
	res := maven.packages with data.lib.cyclonedx.packages as mock_cdx

	some pkg in res
	pkg.repository_url == ""
}

test_spdx_maven_extraction if {
	mock_spdx := [{
		"name": "data-service",
		"purl": "pkg:maven/org.example/data@2.5",
		"externalRefs": [{
			"referenceType": "repository",
			"referenceLocator": "https://internal.jfrog.io/artifactory",
		}],
	}]

	res := maven.packages with data.lib.spdx.packages as mock_spdx

	res == {{
		"name": "data-service",
		"purl": "pkg:maven/org.example/data@2.5",
		"repository_url": "https://internal.jfrog.io/artifactory",
	}}
}

test_spdx_empty_repo_url if {
	mock_spdx := [{
		"name": "no-ref",
		"purl": "pkg:maven/org.example/no-ref@1.0",
		"externalRefs": [{"referenceType": "other", "referenceLocator": "ignore-me"}],
	}]

	res := maven.packages with data.lib.spdx.packages as mock_spdx

	some pkg in res
	pkg.repository_url == ""
}

test_combined_sources if {
	mock_cdx := [{"name": "cdx-pkg", "purl": "pkg:maven/cdx/pkg@1"}]
	mock_spdx := [{"name": "spdx-pkg", "purl": "pkg:maven/spdx/pkg@1"}]

	res := maven.packages with data.lib.cyclonedx.packages as mock_cdx
		with data.lib.spdx.packages as mock_spdx

	count(res) == 2
}
