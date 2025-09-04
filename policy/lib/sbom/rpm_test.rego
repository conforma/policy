package lib.sbom_test

import rego.v1

import data.lib
import data.lib.sbom

test_all_rpm_entities if {
	s_cyclonedx := _cyclonedx_sbom([_cyclonedx_component(_rpm_spam_1, [_cachi2_found_by_property])])
	s_spdx := _spdx_sbom([_spdx_package(_rpm_spam_2, [_cachi2_spdx_annotation])])

	expected := {
		{
			"found_by_cachi2": true,
			"purl": _rpm_spam_1,
		},
		{
			"found_by_cachi2": true,
			"purl": _rpm_spam_2,
		},
	}

	all_sboms := [s_cyclonedx, s_spdx]
	lib.assert_equal_results(expected, sbom.all_rpm_entities) with lib.sbom.all_sboms as all_sboms
}

test_all_rpm_entities_no_dupes if {
	s_cyclonedx := _cyclonedx_sbom([
		_cyclonedx_component(_rpm_spam_1, [_cachi2_found_by_property]),
		_cyclonedx_component(_rpm_spam_2, [_hermeto_found_by_property]),
	])
	s_spdx := _spdx_sbom([
		_spdx_package(_rpm_spam_1, [_cachi2_spdx_annotation]),
		_spdx_package(_rpm_spam_2, [_hermeto_spdx_annotation]),
	])

	# Duplicated entries across SBOMs are ignored.
	expected := {
		{
			"found_by_cachi2": true,
			"purl": _rpm_spam_1,
		},
		{
			"found_by_cachi2": true,
			"purl": _rpm_spam_2,
		},
	}

	all_sboms := [s_cyclonedx, s_spdx]
	lib.assert_equal_results(expected, sbom.all_rpm_entities) with lib.sbom.all_sboms as all_sboms
}

test_rpms_from_sbom_cyclonedx if {
	s := _cyclonedx_sbom([
		_cyclonedx_component(_rpm_spam_1, []),
		_cyclonedx_component(_rpm_spam_2, [_cachi2_found_by_property]),
		_cyclonedx_component(_not_rpm, []),
	])
	expected := {
		{
			"found_by_cachi2": false,
			"purl": _rpm_spam_1,
		},
		{
			"found_by_cachi2": true,
			"purl": _rpm_spam_2,
		},
	}

	lib.assert_equal_results(expected, sbom.rpms_from_sbom(s))
}

test_rpms_from_sbom_spdx if {
	s := _spdx_sbom([
		_spdx_package(_rpm_spam_1, []),
		_spdx_package(_rpm_spam_2, [_cachi2_spdx_annotation]),
		_spdx_package(_not_rpm, []),
	])
	expected := {
		{
			"found_by_cachi2": false,
			"purl": _rpm_spam_1,
		},
		{
			"found_by_cachi2": true,
			"purl": _rpm_spam_2,
		},
	}

	lib.assert_equal_results(expected, sbom.rpms_from_sbom(s))
}

_cyclonedx_sbom(components) := {"components": components}

_cyclonedx_component(purl, properties) := {
	"purl": purl,
	"properties": properties,
}

_spdx_sbom(packages) := {"packages": packages}

_spdx_package(purl, annotations) := {
	"annotations": annotations,
	"externalRefs": [{
		"referenceType": "purl",
		"referenceCategory": "PACKAGE_MANAGER",
		"referenceLocator": purl,
	}],
}

_cachi2_found_by_property := sbom._cachi2_found_by_property("cachi2")

_hermeto_found_by_property := sbom._cachi2_found_by_property("hermeto")

_cachi2_spdx_annotation := {"annotator": "Tool: cachi2:jsonencoded", "annotationType": "OTHER"}

_hermeto_spdx_annotation := {"annotator": "Tool: hermeto:jsonencoded", "annotationType": "OTHER"}

_rpm_spam_1 := "pkg:rpm/redhat/spam@1.0.0-1"

_rpm_spam_2 := "pkg:rpm/redhat/spam@1.0.0-2"

_not_rpm := "pkg:golang/gitplanet.com/bacon@1.2.3?arch=amd64"
