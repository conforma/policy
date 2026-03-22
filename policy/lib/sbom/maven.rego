# METADATA
# title: Maven Package Extraction
# description: >-
#   Extracts Maven packages and their repository URLs from both CycloneDX
#   and SPDX SBOM formats.
package lib.sbom

import future.keywords.contains
import future.keywords.if
import future.keywords.in

# This rule merges with 'packages' defined in other files
# under the same package (e.g., rpm.rego)
packages contains pkg if {
	some p in _cyclonedx_maven_packages
	pkg := p
}

packages contains pkg if {
	some p in _spdx_maven_packages
	pkg := p
}

_cyclonedx_maven_packages contains pkg if {
	some s in cyclonedx_sboms
	some component in s.components

	startswith(component.purl, "pkg:maven/")

	repos := {ref.url |
		some ref in component.externalRefs
		ref.type in ["distribution", "artifact-repository"]
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
		ref.referenceType in ["distribution", "repository"]
	}

	final_repos := _empty_to_default(repos)

	some repo_url in final_repos
	pkg := {
		"purl": item.purl,
		"name": item.name,
		"repository_url": repo_url,
	}
}

_empty_to_default(repo_set) := out if {
	count(repo_set) > 0
	out := repo_set
} else := {""}
