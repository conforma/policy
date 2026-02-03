package lib.sbom.maven

import future.keywords.contains
import future.keywords.if
import future.keywords.in

import data.lib.cyclonedx
import data.lib.spdx

# All Maven packages found in the SBOM, regardless of format.
# Each package contains at least: 'purl', 'name', and 'repository_url'.
packages contains pkg if {
	some p in _cyclonedx_maven_packages
	pkg := p
}

packages contains pkg if {
	some p in _spdx_maven_packages
	pkg := p
}

_cyclonedx_maven_packages contains pkg if {
	some component in cyclonedx.packages
	startswith(component.purl, "pkg:maven/")

	pkg := {
		"purl": component.purl,
		"name": component.name,
		"repository_url": _extract_cdx_repo(component),
	}
}

_extract_cdx_repo(component) := url if {
	some ref in component.externalRefs
	ref.type in ["distribution", "artifact-repository"]
	url := ref.url
}

else := ""

_spdx_maven_packages contains pkg if {
	some item in spdx.packages
	startswith(item.purl, "pkg:maven/")

	pkg := {
		"purl": item.purl,
		"name": item.name,
		"repository_url": _extract_spdx_repo(item),
	}
}

_extract_spdx_repo(item) := url if {
	some ref in item.externalRefs
	ref.referenceType in ["distribution", "repository"]
	url := ref.referenceLocator
}

else := ""
