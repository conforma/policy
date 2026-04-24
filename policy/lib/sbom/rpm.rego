package lib.sbom

import rego.v1

all_rpm_entities contains entity if {
	some sbom in all_sboms
	some entity in rpms_from_sbom(sbom)
}

rpms_from_sbom(s) := entities if {
	# CycloneDX
	entities := {entity |
		some component in s.components
		purl := component.purl
		_is_rpmish(purl)
		entity := {
			"purl": purl,
			"found_by_cachi2": component_found_by_hermeto(component),
		}
	}
	count(entities) > 0
} else := entities if {
	# SPDX
	entities := {entity |
		some pkg in s.packages
		some ref in pkg.externalRefs
		ref.referenceType == "purl"
		ref.referenceCategory in {"PACKAGE_MANAGER", "PACKAGE-MANAGER"}
		purl := ref.referenceLocator
		_is_rpmish(purl)
		entity := {
			"purl": purl,
			"found_by_cachi2": package_found_by_hermeto(pkg),
		}
	}
	count(entities) > 0
}

# Match rpms and modules
# (Use a string match instead of parsing it and checking the type)
_is_rpmish(purl) if {
	startswith(purl, "pkg:rpm/")
} else if {
	startswith(purl, "pkg:rpmmod/")
}

# Exposed for use by tests in rpm_test.rego
_cachi2_found_by_property(name) := hermeto_found_by_property(name)
