package sbom_test

import rego.v1

import data.lib
import data.sbom

test_not_found if {
	expected := {{"code": "sbom.found", "msg": "No SBOM attestations found"}}
	lib.assert_equal_results(expected, sbom.deny) with input.attestations as []
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_not_found_image_index if {
	att := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": [{"results": [
				{
					"name": "IMAGES",
					"type": "string",
					"value": "registry.local/spam@sha256:abc, registry.local/bacon@sha256:bcd",
				},
				{
					"name": "IMAGE_URL",
					"type": "string",
					"value": "registry.local/eggs:latest",
				},
				{
					"name": "IMAGE_DIGEST",
					"type": "string",
					"value": "sha256:fff",
				},
			]}]},
		},
	}}

	lib.assert_empty(sbom.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:fff"
}

test_rule_data_validation if {
	d := {
		"disallowed_packages": [
			# Missing required attributes
			{},
			# Additional properties not allowed
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1.0", "blah": "foo"},
			# Bad types everywhere
			{"purl": 1, "format": 2, "min": 3, "max": 4, "exceptions": [{"subpath": 1}]},
			# Duplicated items
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1.0"},
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1.0"},
			# Bad semver values
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semverv", "min": "v0.1"},
			{"purl": "pkg:golang/k8s.io/client-go", "format": "semver", "max": "v0.1"},
		],
		lib.sbom.rule_data_attributes_key: [
			# ok
			{"name": "some_attr", "value": "some_val"},
			{"name": "no_val_attr"},
			# Missing required attributes
			{},
			# Additional properties not allowed
			{"name": "_name_", "value": "_value_", "something": "else"},
			# Bad types everywhere
			{"name": 1, "value": 2},
			# Duplicated items
			{"name": "_name_", "value": "_value_"},
			{"name": "_name_", "value": "_value_"},
			# Invalid effective on format
			{"name": "_name_", "effective_on": "not-a-date"},
		],
		lib.sbom.rule_data_allowed_external_references_key: [
			{"type": "distribution", "url": "example.com"},
			{"invalid": "foo"},
		],
		lib.sbom.rule_data_disallowed_external_references_key: [
			{"type": "distribution", "url": "badurl"},
			{"invalid": "foo"},
		],
		lib.sbom.rule_data_allowed_package_sources_key: [
			{"type": "generic", "patterns": ["["]},
			{"invalid": "foo"},
		],
	}

	expected := {
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: Must validate at least one schema (anyOf)",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: format is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: min is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 0: purl is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 1: Additional property blah is not allowed",
			"severity": "warning",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_packages has unexpected format: 2.format: 2.format must be one of the following: \"semver\", \"semverv\"",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.max: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.min: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: 2.purl: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Item at index 2 in disallowed_packages does not have a valid PURL: '\\x01'",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_packages has unexpected format: (Root): array items[3,4] must be unique",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Item at index 5 in disallowed_packages does not have a valid min semver value: \"0.1\"",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Item at index 6 in disallowed_packages does not have a valid max semver value: \"0.1\"",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_attributes has unexpected format: 2: name is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_attributes has unexpected format: 3: Additional property something is not allowed",
			"severity": "warning",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_attributes has unexpected format: 4.name: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_attributes has unexpected format: 4.value: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_attributes has unexpected format: (Root): array items[5,6] must be unique",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_attributes has unexpected format: 7.effective_on: Does not match format 'date-time'",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data allowed_external_references has unexpected format: 1: Additional property invalid is not allowed",
			"severity": "warning",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data allowed_external_references has unexpected format: 1: type is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data allowed_external_references has unexpected format: 1: url is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data allowed_package_sources has unexpected format: 0.patterns.0: Does not match format 'regex'",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data allowed_package_sources has unexpected format: 1: Additional property invalid is not allowed",
			"severity": "warning",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data allowed_package_sources has unexpected format: 1: patterns is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data allowed_package_sources has unexpected format: 1: type is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_external_references has unexpected format: 1: Additional property invalid is not allowed",
			"severity": "warning",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_external_references has unexpected format: 1: type is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			"msg": "Rule data disallowed_external_references has unexpected format: 1: url is required",
			"severity": "failure",
		},
		{
			"code": "sbom.disallowed_packages_provided",
			# regal ignore:line-length
			"msg": "Rule data disallowed_packages has unexpected format: 2.exceptions.0.subpath: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(sbom.deny, expected) with input.attestations as _sbom_attestation
		with data.rule_data as d

	# rule data keys are optional
	lib.assert_empty(sbom.deny) with input.attestations as _sbom_attestation
		with data.rule_data as {}
	lib.assert_empty(sbom.deny) with input.attestations as _sbom_attestation
		with data.rule_data as {
			lib.sbom.rule_data_packages_key: [],
			lib.sbom.rule_data_attributes_key: [],
			lib.sbom.rule_data_allowed_package_sources_key: [],
		}
}

_sbom_attestation := [_spdx_sbom_attestation, _cyclonedx_sbom_attestation]

_spdx_sbom_attestation := {"statement": {
	"predicateType": "https://spdx.dev/Document",
	"predicate": {
		"spdxVersion": "SPDX-2.3",
		"documentNamespace": "https://example.dev/spdxdocs/example-310683af-e9a0-4f66-a6a4-119352915b51",
		"dataLicense": "CC0-1.0",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "registry.local/bacon@sha256:123",
		"creationInfo": {
			"created": "2006-08-14T02:34:56-06:00",
			"creators": ["Tool: example SPDX document only"],
		},
		"packages": [{
			"SPDXID": "SPDXRef-image-index",
			"name": "spam",
			"versionInfo": "1.1.2-25",
			"supplier": "Organization: Red Hat",
			"downloadLocation": "NOASSERTION",
			"licenseDeclared": "Apache-2.0",
			"externalRefs": [{
				"referenceCategory": "PACKAGE-MANAGER",
				"referenceType": "purl",
				# regal ignore:line-length
				"referenceLocator": "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
			}],
			"checksums": [{
				"algorithm": "SHA256",
				"checksumValue": "d845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
			}],
		}],
		"files": [{
			"fileName": "/usr/bin/spam",
			"SPDXID": "SPDXRef-File-usr-bin-spam-0e18b4ee77321ba5",
			"checksums": [{
				"algorithm": "SHA256",
				"checksumValue": "d845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
			}],
		}],
	},
}}

_cyclonedx_sbom_attestation := {"statement": {
	"predicateType": "https://cyclonedx.org/bom",
	"predicate": {
		"$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
		"bomFormat": "CycloneDX",
		"specVersion": "1.5",
		"serialNumber": "urn:uuid:cf1a2c3d-bcf8-45c4-9d0f-b2b59a0753f0",
		"version": 1,
		"metadata": {
			"timestamp": "2023-11-20T17:32:41Z",
			"tools": [{
				"vendor": "anchore",
				"name": "syft",
				"version": "0.96.0",
			}],
			"component": {
				"bom-ref": "158c8a990fbd4038",
				"type": "file",
				"name": "/var/lib/containers/storage/vfs/dir/dfd74fe178f4ea0472b5569bff38a4df69d05e7a81b538c98d731566aec15a69",
			},
		},
		"components": [{
			# regal ignore:line-length
			"bom-ref": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3&package-id=f4f4e3cc2a6d9c37",
			"type": "library",
			"publisher": "Red Hat, Inc.",
			"name": "coreutils-single",
			"version": "8.32-34.el9",
			"licenses": [{"license": {"name": "GPLv3+"}}],
			"cpe": "cpe:2.3:a:coreutils-single:coreutils-single:8.32-34.el9:*:*:*:*:*:*:*",
			# regal ignore:line-length
			"purl": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
			"properties": [
				{"name": "attr1"},
				{
					"name": "attr2",
					"value": "value2",
				},
			],
			"externalReferences": [{
				"type": "distribution",
				"url": "https://example.com/file.txt",
			}],
		}],
	},
}}
