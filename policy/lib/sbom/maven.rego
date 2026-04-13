# METADATA
# title: Maven Package Extraction
# description: >-
#   Extracts Maven packages and their repository URLs from both CycloneDX
#   and SPDX SBOM formats.
package lib.sbom

import rego.v1

packages contains pkg if {
	some pkg in _cyclonedx_maven_packages
}

packages contains pkg if {
	some pkg in _spdx_maven_packages
}

_cyclonedx_maven_packages contains pkg if {
	some s in cyclonedx_sboms
	some component in s.components

	startswith(component.purl, "pkg:maven/")

	repos := {ref.url |
		some ref in component.externalRefs
		ref.type in {"distribution", "artifact-repository"}
	}

	final_repos := _empty_to_default(repos)

	some repo_url in final_repos
	pkg := {
		"purl": component.purl,
		"name": component.name,
		"repository_url": repo_url,
	}
}

_spdx_maven_packages contains pkg if {
	some s in spdx_sboms
	some item in s.packages

	startswith(item.purl, "pkg:maven/")

	repos := {ref.referenceLocator |
		some ref in item.externalRefs
		ref.referenceType in {"distribution", "repository"}
	}

	final_repos := _empty_to_default(repos)

	some repo_url in final_repos
	pkg := {
		"purl": item.purl,
		"name": item.name,
		"repository_url": repo_url,
	}
}

# _empty_to_default ensures that packages without explicit repository URLs
# are still processed. If the input repo_set is empty, it returns {""}.
# In the context of this policy, a blank repository URL is considered
# to be Maven Central (https://repo.maven.apache.org/maven2/).
_empty_to_default(repo_set) := repo_set if {
	count(repo_set) > 0
} else := {""}
