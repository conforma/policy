package lib.sbom_test

import data.lib.sbom
import future.keywords.if
import future.keywords.in

test_cyclonedx_maven_extraction if {
	mock_components := [{
		"name": "auth-lib",
		"purl": "pkg:maven/org.example/auth@1.0",
		"externalRefs": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/"}],
	}]

	res := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]

	res == {{
		"name": "auth-lib",
		"purl": "pkg:maven/org.example/auth@1.0",
		"repository_url": "https://repo.maven.apache.org/maven2/",
	}}
}

test_cyclonedx_ignores_non_maven if {
	mock_components := [{"name": "react", "purl": "pkg:npm/react@18.2.0"}]

	res := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]

	count(res) == 0
}

test_cyclonedx_empty_repo_url if {
	mock_components := [{
		"name": "no-repo",
		"purl": "pkg:maven/org.example/no-repo@1.0",
		"externalRefs": [],
	}]

	res := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]

	some pkg in res
	pkg.repository_url == ""
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

	res := sbom.packages with sbom.spdx_sboms as [_spdx_sbom(mock_packages)]

	res == {{
		"name": "data-service",
		"purl": "pkg:maven/org.example/data@2.5",
		"repository_url": "https://internal.jfrog.io/artifactory",
	}}
}

test_combined_sources if {
	mock_cdx := [{"name": "cdx-pkg", "purl": "pkg:maven/cdx/pkg@1", "externalRefs": [{"type": "distribution", "url": "url1"}]}]
	mock_spdx := [{"name": "spdx-pkg", "purl": "pkg:maven/spdx/pkg@1", "externalRefs": [{"referenceType": "repository", "referenceLocator": "url2"}]}]

	# Verify that sbom.packages merges results from both arrays
	res := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_cdx)]
		with sbom.spdx_sboms as [_spdx_sbom(mock_spdx)]

	count(res) == 2
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

	pkg_list := sbom.packages with sbom.cyclonedx_sboms as [_cyclonedx_sbom(mock_components)]

	count(pkg_list) == 2
	urls := {p.repository_url | some p in pkg_list}
	urls == {"https://repo-a.com", "https://repo-b.com"}
}

_cyclonedx_sbom(components) := {"components": components}

_spdx_sbom(packages) := {"packages": packages}
