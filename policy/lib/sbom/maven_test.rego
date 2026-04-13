package lib.sbom_test

import data.lib
import data.lib.sbom
import future.keywords.if
import future.keywords.in

test_cyclonedx_maven_extraction if {
	mock_components := [{
		"name": "auth-lib",
		"purl": "pkg:maven/org.example/auth@1.0",
		"externalRefs": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/"}],
	}]

	expected := {{
		"name": "auth-lib",
		"purl": "pkg:maven/org.example/auth@1.0",
		"repository_url": "https://repo.maven.apache.org/maven2/",
	}}

	result := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]

	lib.assert_equal(expected, result)
}

test_cyclonedx_ignores_non_maven if {
	mock_components := [{"name": "react", "purl": "pkg:npm/react@18.2.0"}]

	lib.assert_empty(sbom.packages) with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]
}

test_cyclonedx_empty_repo_url if {
	mock_components := [{
		"name": "no-repo",
		"purl": "pkg:maven/org.example/no-repo@1.0",
		"externalRefs": [],
	}]

	expected := {{
		"name": "no-repo",
		"purl": "pkg:maven/org.example/no-repo@1.0",
		"repository_url": "",
	}}

	result := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]

	lib.assert_equal(expected, result)
}

test_spdx_maven_extraction if {
	mock_packages := [{
		"name": "data-service",
		"purl": "pkg:maven/org.example/data@2.5",
		"externalRefs": [{
			"referenceType": "repository",
			"referenceLocator": "https://internal.jfrog.io/artifactory",
		}],
	}]

	expected := {{
		"name": "data-service",
		"purl": "pkg:maven/org.example/data@2.5",
		"repository_url": "https://internal.jfrog.io/artifactory",
	}}

	result := sbom.packages with sbom.spdx_sboms as [_spdx_sbom(mock_packages)]

	lib.assert_equal(expected, result)
}

test_combined_sources if {
	mock_cdx := [{
		"name": "cdx-pkg",
		"purl": "pkg:maven/cdx/pkg@1",
		"externalRefs": [{"type": "distribution", "url": "url1"}],
	}]

	mock_spdx := [{
		"name": "spdx-pkg",
		"purl": "pkg:maven/spdx/pkg@1",
		"externalRefs": [{
			"referenceType": "repository",
			"referenceLocator": "url2",
		}],
	}]

	expected := {
		{
			"name": "cdx-pkg",
			"purl": "pkg:maven/cdx/pkg@1",
			"repository_url": "url1",
		},
		{
			"name": "spdx-pkg",
			"purl": "pkg:maven/spdx/pkg@1",
			"repository_url": "url2",
		},
	}

	result := sbom.packages
		with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_cdx)]
		with sbom.spdx_sboms as [_spdx_sbom(mock_spdx)]

	lib.assert_equal(expected, result)
}

test_cyclonedx_multiple_repo_capture if {
	mock_components := [{
		"name": "multi-repo-lib",
		"purl": "pkg:maven/org.example/multi@1.0",
		"externalRefs": [
			{"type": "distribution", "url": "https://repo-a.com"},
			{"type": "artifact-repository", "url": "https://repo-b.com"},
		],
	}]

	expected := {
		{
			"name": "multi-repo-lib",
			"purl": "pkg:maven/org.example/multi@1.0",
			"repository_url": "https://repo-a.com",
		},
		{
			"name": "multi-repo-lib",
			"purl": "pkg:maven/org.example/multi@1.0",
			"repository_url": "https://repo-b.com",
		},
	}

	result := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]

	lib.assert_equal(expected, result)
}

_cyclonedx_sbom(components) := {"components": components}

_spdx_sbom(packages) := {"packages": packages}
