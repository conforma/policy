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
			"found_by_cachi2": _component_found_by_cachi2(component),
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
			"found_by_cachi2": _package_found_by_cachi2(pkg),
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

# CycloneDX style
_component_found_by_cachi2(component) if {
	some property in component.properties
	some cachi2_name in _cachi2_names
	property == _cachi2_found_by_property(cachi2_name)
} else := false

# Expecting this to be called with one of _cachi2_names
_cachi2_found_by_property(cachi2_name) := {
	"name": sprintf("%s:found_by", [cachi2_name]),
	"value": cachi2_name,
}

# SPDX style
_package_found_by_cachi2(pkg) if {
	some annotation in pkg.annotations
	some cachi2_name in _cachi2_names
	regex.match(sprintf(`.*%s.*`, [cachi2_name]), annotation.annotator)
	annotation.annotationType == "OTHER"
	# `comment` contains additional information, but that is not needed for the purpose of
	# simply filtering what was found by cachi2.
} else := false

# The new name for cachi2 is hermeto. We want to treat them
# as as synonymous when looking in the SBOM data.
_cachi2_names := ["cachi2", "hermeto"]
