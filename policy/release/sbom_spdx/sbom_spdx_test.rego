package sbom_spdx_test

import rego.v1

import data.lib
import data.lib.sbom
import data.sbom_spdx

test_all_good if {
	lib.assert_empty(sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_all_good_marshaled if {
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate",
		"value": json.marshal(_sbom_attestation.statement.predicate),
	}])
	lib.assert_empty(sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_missing_packages if {
	expected := {{"code": "sbom_spdx.contains_packages", "msg": "The list of packages is empty"}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages",
		"value": [],
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_missing_files if {
	expected := {{"code": "sbom_spdx.contains_files", "msg": "The list of files is empty"}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/files",
		"value": [],
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_digest_mismatch if {
	expected := {{
		"code": "sbom_spdx.matches_image",
		"msg": "Image digest in the SBOM, \"sha256:123\", is not as expected, \"sha256:abc\"",
	}}
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:abc"
}

test_not_valid if {
	expected := {{
		"code": "sbom_spdx.valid",
		"msg": "SPDX SBOM at index 0 is not valid: packages: Invalid type. Expected: array, given: string",
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages",
		"value": "spam",
	}])
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
}

test_not_allowed_with_min if {
	disallowed_packages := [{
		"purl": "pkg:golang/k8s.io/client-go",
		"format": "semverv",
		"min": "v50.28.3",
	}]

	# Much lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v0.29.4", disallowed_packages)

	# Lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.28.2", disallowed_packages)

	# Exact match to min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.3", disallowed_packages)

	# Higher than min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.4", disallowed_packages)

	# Much higher than min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v99.99.99", disallowed_packages)
}

assert_allowed(purl, disallowed_packages) if {
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages/0/externalRefs/0/referenceLocator",
		"value": purl,
	}])

	# regal ignore:with-outside-test-context
	lib.assert_empty(sbom_spdx.deny) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

assert_not_allowed(purl, disallowed_packages) if {
	expected := {{
		"code": "sbom_spdx.allowed",
		"msg": sprintf("Package is not allowed: %s", [purl]),
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages/0/externalRefs/0/referenceLocator",
		"value": purl,
	}])

	# regal ignore:with-outside-test-context
	lib.assert_equal_results(sbom_spdx.deny, expected) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

test_external_references_allowed_regex_with_no_rules_is_allowed if {
	expected := {}
	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_allowed_external_references_key: []}
}

test_external_references_allowed_regex if {
	expected := {{
		"code": "sbom_spdx.allowed_package_external_references",
		# regal ignore:line-length
		"msg": `Package spam has reference "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98" of type "purl" which is not explicitly allowed by pattern ".*allowed.net.*"`,
	}}

	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_allowed_external_references_key: [{
			"type": "purl",
			"url": ".*allowed.net.*",
		}]}
}

test_external_references_disallowed_regex if {
	expected := {{
		"code": "sbom_spdx.disallowed_package_external_references",
		# regal ignore:line-length
		"msg": `Package spam has reference "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98" of type "purl" which is disallowed by pattern ".*kernel-module-management-rhel9-operator.*"`,
	}}

	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_disallowed_external_references_key: [{
			"type": "purl",
			"url": ".*kernel-module-management-rhel9-operator.*",
		}]}
}

test_allowed_package_sources if {
	expected := {{
		"code": "sbom_spdx.allowed_package_sources",
		"term": "pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz",
		# regal ignore:line-length
		"msg": `Package pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz fetched by Hermeto was sourced from "https://openssl.org/source/openssl-1.1.0g.tar.gz" which is not allowed`,
	}}

	att := json.patch(_sbom_attestation, [
		{
			"op": "add",
			"path": "/statement/predicate/packages/-",
			"value": {
				"SPDXID": "openssl",
				"name": "openssl",
				"versionInfo": "None",
				"externalRefs": [{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType": "purl",
					"referenceLocator": "pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz",
				}],
				"annotations": [{
					"annotator": "Tool: hermeto:jsonencoded",
					"comment": "{\"name\":\"hermeto:found_by\",\"value\":\"hermeto\"}",
					"annotationDate": "2024-12-09T12:00:00Z",
					"annotationType": "OTHER",
				}],
				"downloadLocation": "NOASSERTION",
			},
		},
		{
			"op": "add",
			"path": "/statement/predicate/packages/-",
			"value": {
				"SPDXID": "batik-anim",
				"name": "batik-anim",
				"versionInfo": "None",
				"externalRefs": [{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType": "purl",
					# regal ignore:line-length
					"referenceLocator": "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=pom&download_url=https://repo.maven.apache.org/maven2/org/apache/xmlgraphics/batik-anim/1.9.1/batik-anim-1.9.1.pom",
				}],
				"annotations": [{
					"annotator": "Tool: hermeto:jsonencoded",
					"comment": "{\"name\":\"hermeto:found_by\",\"value\":\"hermeto\"}",
					"annotationDate": "2024-12-09T12:00:00Z",
					"annotationType": "OTHER",
				}],
				"downloadLocation": "NOASSERTION",
			},
		},
		{
			"op": "add",
			"path": "/statement/predicate/packages/-",
			"value": {
				"SPDXID": "unrelated",
				"name": "unrelated",
				"versionInfo": "None",
				"externalRefs": [{
					"referenceCategory": "PACKAGE-MANAGER",
					"referenceType": "purl",
					"referenceLocator": "pkg:generic/unrelated?download_url=https://irrelevant.org",
				}],
				"annotations": [{
					"annotator": "Tool: hermeto:jsonencoded",
					"comment": "{\"name\":\"irrelevant\",\"value\":\"im-irrelevant\"}",
					"annotationDate": "2024-12-09T12:00:00Z",
					"annotationType": "OTHER",
				}],
				"downloadLocation": "NOASSERTION",
			},
		},
	])

	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [att]
		with data.rule_data as {sbom.rule_data_allowed_package_sources_key: [
			{
				"type": "maven",
				"patterns": [".*apache.org.*", ".*example.com.*"],
			},
			{
				"type": "generic",
				"patterns": [".*apache.org.*", ".*example.com.*"],
			},
		]}
}

test_attributes_not_allowed_pair if {
	expected := {{
		"code": "sbom_spdx.disallowed_package_attributes",
		# regal ignore:line-length
		"term": "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
		# regal ignore:line-length
		"msg": `Package pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98 has the attribute "attr1" set`,
	}}

	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "attr1"}]}
}

test_attributes_not_allowed_value if {
	expected := {{
		"code": "sbom_spdx.disallowed_package_attributes",
		# regal ignore:line-length
		"term": "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
		# regal ignore:line-length
		"msg": `Package pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98 has the attribute "attr2" set to "value2"`,
	}}

	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "attr2", "value": "value2"}]}
}

test_attributes_not_allowed_effective_on if {
	expected := {
		{
			"code": "sbom_spdx.disallowed_package_attributes",
			# regal ignore:line-length
			"term": "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
			# regal ignore:line-length
			"msg": `Package pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98 has the attribute "attr1" set`,
			"effective_on": "2025-01-01T00:00:00Z",
		},
		{
			"code": "sbom_spdx.disallowed_package_attributes",
			# regal ignore:line-length
			"term": "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
			# regal ignore:line-length
			"msg": `Package pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98 has the attribute "attr2" set to "value2"`,
			"effective_on": "2025-02-04T00:00:00Z",
		},
	}

	raw_results := sbom_spdx.deny with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [
			{"name": "attr1", "effective_on": "2025-01-01T00:00:00Z"},
			{"name": "attr2", "value": "value2"},
		]}

	results := {result_no_collections |
		some result in raw_results
		result_no_collections := json.remove(result, ["collections"])
	}

	lib.assert_equal(expected, results)
}

test_attributes_multiple_external_refs if {
	_sbom := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/packages/0/externalRefs/-",
		"value": {
			"referenceCategory": "SECURITY",
			"referenceType": "cpe23Type",
			"referenceLocator": "cpe:2.3:o:example:example:1.0:*:*:*:*:*:*:*",
		},
	}])

	expected := {
		{
			"code": "sbom_spdx.disallowed_package_attributes",
			"msg": `Package cpe:2.3:o:example:example:1.0:*:*:*:*:*:*:* has the attribute "attr2" set to "value2"`,
			"term": "cpe:2.3:o:example:example:1.0:*:*:*:*:*:*:*",
		},
		{
			"code": "sbom_spdx.disallowed_package_attributes",
			# regal ignore:line-length
			"term": "pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98",
			# regal ignore:line-length
			"msg": `Package pkg:oci/kernel-module-management-rhel9-operator@sha256%3Ad845f0bd93dad56c92c47e8c116a11a0cc5924c0b99aed912b4f8b54178efa98 has the attribute "attr2" set to "value2"`,
		},
	}

	lib.assert_equal_results(expected, sbom_spdx.deny) with input.attestations as [_sbom]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "attr2", "value": "value2"}]}
}

_sbom_attestation := {"statement": {
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
			"annotations": [
				{
					"annotator": "Tool: konflux:jsonencoded",
					"comment": "{\"name\":\"attr1\"}",
					"annotationDate": "2024-12-09T12:00:00Z",
					"annotationType": "OTHER",
				},
				{
					"annotator": "Tool: konflux:jsonencoded",
					"comment": "{\"name\":\"attr2\", \"value\":\"value2\"}",
					"annotationDate": "2024-12-09T12:00:00Z",
					"annotationType": "OTHER",
				},
			],
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
