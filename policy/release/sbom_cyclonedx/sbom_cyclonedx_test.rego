package sbom_cyclonedx_test

import rego.v1

import data.lib
import data.lib.sbom
import data.sbom_cyclonedx

test_all_good_from_attestation if {
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_all_good_from_image if {
	files := {"root/buildinfo/content_manifests/sbom-cyclonedx.json": _sbom_attestation.statement.predicate}
	lib.assert_empty(sbom_cyclonedx.deny) with input.image.files as files
		with input.image.ref as "registry.local/spam@sha256:123"
}

test_not_valid if {
	expected := {{
		"code": "sbom_cyclonedx.valid",
		"msg": "CycloneDX SBOM at index 0 is not valid: components: Invalid type. Expected: array, given: string",
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components",
		"value": "spam",
	}])
	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [att]
}

test_attributes_not_allowed_all_good if {
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"

	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "attrX", "value": "valueX"}]}
}

test_attributes_not_allowed_pair if {
	expected := {{
		"code": "sbom_cyclonedx.disallowed_package_attributes",
		# regal ignore:line-length
		"term": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
		# regal ignore:line-length
		"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has the attribute "attr1" set`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "attr1"}]}
}

test_attributes_not_allowed_value if {
	expected := {{
		"code": "sbom_cyclonedx.disallowed_package_attributes",
		# regal ignore:line-length
		"term": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
		# regal ignore:line-length
		"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has the attribute "attr2" set to "value2"`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "attr2", "value": "value2"}]}
}

test_attributes_not_allowed_effective_on if {
	expected := {
		{
			"code": "sbom_cyclonedx.disallowed_package_attributes",
			# regal ignore:line-length
			"term": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
			# regal ignore:line-length
			"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has the attribute "attr1" set`,
			"effective_on": "2025-01-01T00:00:00Z",
		},
		{
			"code": "sbom_cyclonedx.disallowed_package_attributes",
			# regal ignore:line-length
			"term": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
			# regal ignore:line-length
			"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has the attribute "attr2" set to "value2"`,
			"effective_on": "2024-07-31T00:00:00Z",
		},
	}

	raw_results := sbom_cyclonedx.deny with input.attestations as [_sbom_attestation]
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

test_attributes_not_allowed_value_no_purl if {
	expected := {{
		"code": "sbom_cyclonedx.disallowed_package_attributes",
		"term": "rhel",
		# regal ignore:line-length
		"msg": `Package rhel has the attribute "syft:distro:id" set to "rhel"`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "syft:distro:id", "value": "rhel"}]}
}

test_external_references_allowed_regex_with_no_rules_is_allowed if {
	expected := {}
	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_allowed_external_references_key: []}
}

test_external_references_allowed_regex if {
	expected := {{
		"code": "sbom_cyclonedx.allowed_package_external_references",
		# regal ignore:line-length
		"term": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
		# regal ignore:line-length
		"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has reference "https://example.com/file.txt" of type "distribution" which is not explicitly allowed by pattern ".*allowed.net.*"`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_allowed_external_references_key: [{
			"type": "distribution",
			"url": ".*allowed.net.*",
		}]}
}

test_external_references_allowed_no_purl if {
	expected := {{
		"code": "sbom_cyclonedx.allowed_package_external_references",
		"term": "rhel",
		# regal ignore:line-length
		"msg": `Package rhel has reference "https://www.redhat.com/" of type "website" which is not explicitly allowed by pattern ".*example.com.*"`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_allowed_external_references_key: [{
			"type": "website",
			"url": ".*example.com.*",
		}]}
}

test_external_references_disallowed_regex if {
	expected := {{
		"code": "sbom_cyclonedx.disallowed_package_external_references",
		# regal ignore:line-length
		"term": "pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3",
		# regal ignore:line-length
		"msg": `Package pkg:rpm/rhel/coreutils-single@8.32-34.el9?arch=x86_64&upstream=coreutils-8.32-34.el9.src.rpm&distro=rhel-9.3 has reference "https://example.com/file.txt" of type "distribution" which is disallowed by pattern ".*example.com.*"`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_disallowed_external_references_key: [{
			"type": "distribution",
			"url": ".*example.com.*",
		}]}
}

test_external_references_disallowed_no_purl if {
	expected := {{
		"code": "sbom_cyclonedx.disallowed_package_external_references",
		"term": "rhel",
		# regal ignore:line-length
		"msg": `Package rhel has reference "https://www.redhat.com/" of type "website" which is disallowed by pattern ".*redhat.com.*"`,
	}}

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [_sbom_attestation]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_disallowed_external_references_key: [{
			"type": "website",
			"url": ".*redhat.com.*",
		}]}
}

test_allowed_package_sources if {
	expected := {{
		"code": "sbom_cyclonedx.allowed_package_sources",
		"term": "pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz",
		# regal ignore:line-length
		"msg": `Package pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz fetched by Hermeto was sourced from "https://openssl.org/source/openssl-1.1.0g.tar.gz" which is not allowed`,
	}}

	att := json.patch(_sbom_attestation, [
		{
			"op": "add",
			"path": "/statement/predicate/components/-",
			"value": {
				"type": "file",
				"name": "openssl",
				"purl": "pkg:generic/openssl@1.1.10g?download_url=https://openssl.org/source/openssl-1.1.0g.tar.gz",
				"properties": [{
					"name": "hermeto:found_by",
					"value": "hermeto",
				}],
				"externalReferences": [{"type": "distribution", "url": "https://openssl.org/source/openssl-1.1.0g.tar.gz"}],
			},
		},
		{
			"op": "add",
			"path": "/statement/predicate/components/-",
			"value": {
				"type": "library",
				"name": "batik-anim",
				"purl": "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=pom",
				"properties": [{
					"name": "hermeto:found_by",
					"value": "hermeto",
				}],
				# regal ignore:line-length
				"externalReferences": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/org/apache/xmlgraphics/batik-anim/1.9.1/batik-anim-1.9.1.pom"}],
			},
		},
		{
			"op": "add",
			"path": "/statement/predicate/components/-",
			"value": {
				"type": "file",
				"name": "unrelated",
				"purl": "pkg:generic/unrelated",
				"externalReferences": [{"type": "distribution", "url": "https://irrelevant.org"}],
			},
		},
	])

	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [att]
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

test_allowed_package_sources_no_rule_defined if {
	expected := {{
		"code": "sbom_cyclonedx.allowed_package_sources",
		"term": "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=pom",
		# regal ignore:line-length
		"msg": `Package pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=pom fetched by Hermeto was sourced from "https://repo.maven.apache.org/maven2/org/apache/xmlgraphics/batik-anim/1.9.1/batik-anim-1.9.1.pom" which is not allowed`,
	}}

	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components/-",
		"value": {
			"type": "library",
			"name": "batik-anim",
			"purl": "pkg:maven/org.apache.xmlgraphics/batik-anim@1.9.1?type=pom",
			"properties": [{
				"name": "hermeto:found_by",
				"value": "hermeto",
			}],
			# regal ignore:line-length
			"externalReferences": [{"type": "distribution", "url": "https://repo.maven.apache.org/maven2/org/apache/xmlgraphics/batik-anim/1.9.1/batik-anim-1.9.1.pom"}],
		},
	}])

	# rule data is defined only for purl of type generic
	lib.assert_equal_results(expected, sbom_cyclonedx.deny) with input.attestations as [att]
		with data.rule_data as {sbom.rule_data_allowed_package_sources_key: [{
			"type": "generic",
			"patterns": [".*example.com.*"],
		}]}
}

test_attributes_not_allowed_no_properties if {
	att := json.patch(_sbom_attestation, [{
		"op": "remove",
		"path": "/statement/predicate/components/0/properties",
	}])

	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [att]
		with input.image.ref as "registry.local/spam@sha256:123"
		with data.rule_data as {sbom.rule_data_attributes_key: [{"name": "attr", "value": "value"}]}
}

test_allowed_by_default if {
	assert_allowed("pkg:golang/k8s.io/client-go@v0.28.3", [])
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

test_not_allowed_with_max if {
	disallowed_packages := [{
		"purl": "pkg:golang/k8s.io/client-go",
		"format": "semverv",
		"max": "v50.28.3",
	}]

	# Much lower than max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v0.29.4", disallowed_packages)

	# Lower than max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.2", disallowed_packages)

	# Exact match to max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.3", disallowed_packages)

	# Higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.28.4", disallowed_packages)

	# Much higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v99.99.99", disallowed_packages)
}

test_not_allowed_with_subpaths if {
	disallowed_packages := [{
		"purl": "pkg:golang/github.com/hashicorp/consul",
		"format": "semverv",
		"min": "v1.29.2",
		"exceptions": [
			{"subpath": "api"},
			{"subpath": "sdk"},
		],
	}]

	# Unknown subpath matches
	assert_not_allowed("pkg:golang/github.com/hashicorp/consul@v1.29.2#spam", disallowed_packages)

	# Missing subpath matches
	assert_not_allowed("pkg:golang/github.com/hashicorp/consul@v1.29.2#", disallowed_packages)
	assert_not_allowed("pkg:golang/github.com/hashicorp/consul@v1.29.2", disallowed_packages)

	# Excluded subpaths do not match
	assert_allowed("pkg:golang/github.com/hashicorp/consul@v1.29.2#api", disallowed_packages)
	assert_allowed("pkg:golang/github.com/hashicorp/consul@v1.29.2#sdk", disallowed_packages)
}

test_not_allowed_with_min_max if {
	disallowed_packages := [{
		"purl": "pkg:golang/k8s.io/client-go",
		"format": "semverv",
		"min": "v50.20.2",
		"max": "v50.28.3",
	}]

	# Much lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v0.29.4", disallowed_packages)

	# Lower than min version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.20.1", disallowed_packages)

	# Exact match to min version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.20.2", disallowed_packages)

	# Mid-range
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.24.9", disallowed_packages)

	# Exact match to max version
	assert_not_allowed("pkg:golang/k8s.io/client-go@v50.28.3", disallowed_packages)

	# Higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v50.28.4", disallowed_packages)

	# Much higher than max version
	assert_allowed("pkg:golang/k8s.io/client-go@v99.99.99", disallowed_packages)
}

assert_allowed(purl, disallowed_packages) if {
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components/0/purl",
		"value": purl,
	}])

	# regal ignore:with-outside-test-context
	lib.assert_empty(sbom_cyclonedx.deny) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

assert_not_allowed(purl, disallowed_packages) if {
	expected := {{
		"code": "sbom_cyclonedx.allowed",
		"msg": sprintf("Package is not allowed: %s", [purl]),
	}}
	att := json.patch(_sbom_attestation, [{
		"op": "add",
		"path": "/statement/predicate/components/0/purl",
		"value": purl,
	}])

	# regal ignore:with-outside-test-context
	lib.assert_equal_results(sbom_cyclonedx.deny, expected) with input.attestations as [att]
		with data.rule_data.disallowed_packages as disallowed_packages
}

_sbom_attestation := {"statement": {
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
		"components": [
			{
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
			},
			{
				"bom-ref": "os:rhel@9.4",
				"type": "operating-system",
				"name": "rhel",
				"version": "9.4",
				"description": "Red Hat Enterprise Linux 9.4 (Plow)",
				"cpe": "cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*",
				"swid": {
					"tagId": "rhel",
					"name": "rhel",
					"version": "9.4",
				},
				"externalReferences": [
					{
						"url": "https://bugzilla.redhat.com/",
						"type": "issue-tracker",
					},
					{
						"url": "https://www.redhat.com/",
						"type": "website",
					},
				],
				"properties": [
					{
						"name": "syft:distro:id",
						"value": "rhel",
					},
					{
						"name": "syft:distro:idLike:0",
						"value": "fedora",
					},
					{
						"name": "syft:distro:prettyName",
						"value": "Red Hat Enterprise Linux 9.4 (Plow)",
					},
					{
						"name": "syft:distro:versionID",
						"value": "9.4",
					},
				],
			},
		],
	},
}}
