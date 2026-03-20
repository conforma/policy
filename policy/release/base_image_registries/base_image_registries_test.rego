package base_image_registries_test

import rego.v1

import data.base_image_registries
import data.lib

# There are two formats of SBOM supported, CycloneDX and SPDX. In these tests,
# the mocked CycloneDX SBOMS are generally defined inline in the test, while
# the mocked SPDX SBOMS are defined in one place at the bottom, and then patched
# in each test as required. Todo maybe: Make it more consistent, perhaps with
# some helper functions for generating mocked sbom components/packages.

test_allowed_base_images if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "ubi7",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
			# regal ignore:line-length
			"purl": "pkg:oci/ubi@sha256:abc0000000000000000000000000000000000000000000000000000000000abc?repository_url=registry.redhat.io/ubi7",
		}]},
		{"components": [{
			"name": "registry",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
			# regal ignore:line-length
			"purl": "pkg:oci/registry@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd?repository_url=docker.io/library/registry",
		}]},
	]}]

	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as _spdx_sbom
}

test_allowed_base_images_from_snapshot if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "ubi7",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
			# regal ignore:line-length
			"purl": "pkg:oci/ubi@sha256:abc0000000000000000000000000000000000000000000000000000000000abc?repository_url=registry.redhat.io/ubi7",
		}]},
		{"components": [{
			"name": "registry",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
			# regal ignore:line-length
			"purl": "pkg:oci/registry@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd?repository_url=docker.io/library/registry",
		}]},
	]}]

	snapshot := {"components": [
		{"containerImage": "ignored.io/ignore@sha256:abc0000000000000000000000000000000000000000000000000000000000abc"},
		# regal ignore:line-length
		{"containerImage": "ignored.dev/ignore:ignore@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd"},
	]}

	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as _spdx_sbom
		with data.rule_data.allowed_registry_prefixes as ["another.registry.io"]
		with input.snapshot as snapshot
}

test_empty_base_images_result if {
	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as [{}] with lib.sbom.spdx_sboms as [{}]
}

test_disallowed_base_images if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "3",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
			"purl": "pkg:oci/3@sha256:6123?repository_url=registry.redhat.yo/ubi7/3",
		}]},
		{"components": [{
			"name": "3",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
			"purl": "pkg:oci/3@sha256:6123?repository_url=dockery.io/busybox/3",
		}]},
		{"components": [{
			"name": "3",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "1",
			}],
			"purl": "pkg:oci/3@sha256:6123?repository_url=registry.redhat.ioo/spam/3",
		}]},
	]}]

	bad_spdx_sbom := json.patch(_spdx_sbom, [
		# Tweak the repository_url so they're no longer allowed
		# regal ignore:line-length
		{"op": "replace", "path": "/0/packages/0/externalRefs/0/referenceLocator", "value": "pkg:oci/ignored@sha256:1230000000000000000000000000000000000000000000000000000000000123?repository_url=registry.redhat.blah/ubi7/3"},
		# regal ignore:line-length
		{"op": "replace", "path": "/0/packages/1/externalRefs/0/referenceLocator", "value": "pkg:oci/ignored@sha256:456?repository_url=registry.redhat.whatever/ubi7/3"},
		# Actually these two won't matter, but let's change them anyhow so the name and repository_url are consistent
		{"op": "replace", "path": "/0/packages/0/name", "value": "registry.redhat.blah/ubi7/3"},
		{"op": "replace", "path": "/0/packages/1/name", "value": "registry.redhat.whatever/ubi7/3"},
	])

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.yo/ubi7/3@sha256:6123\" is from a disallowed registry",
			"term": "registry.redhat.yo/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.ioo/spam/3@sha256:6123\" is from a disallowed registry",
			"term": "registry.redhat.ioo/spam/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"dockery.io/busybox/3@sha256:6123\" is from a disallowed registry",
			"term": "dockery.io/busybox/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			# regal ignore:line-length
			"msg": "Base image \"registry.redhat.blah/ubi7/3@sha256:1230000000000000000000000000000000000000000000000000000000000123\" is from a disallowed registry",
			"term": "registry.redhat.blah/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.whatever/ubi7/3@sha256:456\" is from a disallowed registry",
			"term": "registry.redhat.whatever/ubi7/3",
		},
	}
	lib.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as bad_spdx_sbom
}

test_disallowed_base_images_with_snapshot if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "ubi7",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "true",
			}],
			# regal ignore:line-length
			"purl": "pkg:oci/ubi@sha256:abc0000000000000000000000000000000000000000000000000000000000abc?repository_url=registry.redhat.io/ubi7",
		}]},
		{"components": [{
			"name": "registry",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
			# regal ignore:line-length
			"purl": "pkg:oci/registry@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd?repository_url=docker.io/library/registry",
		}]},
	]}]

	bad_spdx_sbom := json.patch(_spdx_sbom, [
		# Tweak the repository_url so they're no longer allowed
		# regal ignore:line-length
		{"op": "replace", "path": "/0/packages/0/externalRefs/0/referenceLocator", "value": "pkg:oci/3@sha256:ccc0000000000000000000000000000000000000000000000000000000000ccc?repository_url=registry.redhat.blah/ubi7/3"},
		# regal ignore:line-length
		{"op": "replace", "path": "/0/packages/1/externalRefs/0/referenceLocator", "value": "pkg:oci/3@sha256:ddd0000000000000000000000000000000000000000000000000000000000ddd?repository_url=registry.redhat.whatever/ubi7/3"},
		# Actually these two won't matter, but let's change them anyhow so the name and repository_url are consistent
		{"op": "replace", "path": "/0/packages/0/name", "value": "3"},
		{"op": "replace", "path": "/0/packages/1/name", "value": "3"},
	])

	snapshot := {"components": [
		{"containerImage": "ignored.io/ignore@sha256:cba0000000000000000000000000000000000000000000000000000000000cba"},
		# regal ignore:line-length
		{"containerImage": "ignored.dev/ignore:ignore@sha256:dcb0000000000000000000000000000000000000000000000000000000000dcb"},
	]}

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			# regal ignore:line-length
			"msg": "Base image \"docker.io/library/registry@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd\" is from a disallowed registry",
			"term": "docker.io/library/registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			# regal ignore:line-length
			"msg": "Base image \"registry.redhat.io/ubi7@sha256:abc0000000000000000000000000000000000000000000000000000000000abc\" is from a disallowed registry",
			"term": "registry.redhat.io/ubi7",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			# regal ignore:line-length
			"msg": "Base image \"registry.redhat.blah/ubi7/3@sha256:ccc0000000000000000000000000000000000000000000000000000000000ccc\" is from a disallowed registry",
			"term": "registry.redhat.blah/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			# regal ignore:line-length
			"msg": "Base image \"registry.redhat.whatever/ubi7/3@sha256:ddd0000000000000000000000000000000000000000000000000000000000ddd\" is from a disallowed registry",
			"term": "registry.redhat.whatever/ubi7/3",
		},
	}

	lib.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as bad_spdx_sbom
		with data.rule_data.allowed_registry_prefixes as ["another.registry.io"]
		with input.snapshot as snapshot
}

test_sbom_base_image_selection if {
	sboms := [{"formulation": [
		{"components": [{
			"name": "no-properties",
			"type": "container",
			"purl": "pkg:oci/no-properties@sha256:6123?repository_url=registry.ignore.me/no-properties",
		}]},
		{"components": [{
			"name": "value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "false",
			}],
			"purl": "pkg:oci/value@sha256:6123?repository_url=registry.ignore.me/is_base_image/false/value",
		}]},
		{"components": [{
			"name": "value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": "0",
			}],
		}]},
		{"components": [{
			"name": "registry.ignore.me/is_base_image/non-marshaled-json/value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_base_image",
				"value": true,
			}],
			"purl": "pkg:oci/value@sha256:6123?repository_url=registry.ignore.me/is_base_image/non-marshaled-json/value",
		}]},
		{"components": [{
			"name": "value",
			"type": "container",
			"properties": [{"name": "konflux:container:is_base_image"}],
			"purl": "pkg:oci/value@sha256:6123?repository_url=registry.ignore.me/is_base_image/missing/value",
		}]},
		{"components": [{
			"name": "value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "false",
			}],
			"purl": "pkg:oci/value@sha256:6123?repository_url=registry.ignore.me/for_stage/false/value",
		}]},
		{"components": [{
			"name": "value",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": 1,
			}],
			"purl": "pkg:oci/value@sha256:6123?repository_url=registry.ignore.me/for_stage/non-marshaled-json/value",
		}]},
		{"components": [{
			"name": "value",
			"type": "container",
			"properties": [{"name": "konflux:container:is_builder_image:for_stage"}],
			"purl": "pkg:oci/value@sha256:6123?repository_url=registry.ignore.me/for_stage/missing/value",
		}]},
	]}]

	lib.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as []
}

test_base_image_not_found if {
	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images information is missing",
	}}
	lib.assert_equal_results(base_image_registries.deny, expected)
}

test_base_image_not_found_image_index if {
	att := {"statement": {"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"buildConfig": {"tasks": [{"results": [
			{
				"name": "IMAGES",
				"type": "string",
				# regal ignore:line-length
				"value": "registry.local/spam@sha256:abc0000000000000000000000000000000000000000000000000000000000abc, registry.local/bacon@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd",
			},
			{
				"name": "IMAGE_URL",
				"type": "string",
				"value": "registry.local/eggs:latest",
			},
			{
				"name": "IMAGE_DIGEST",
				"type": "string",
				"value": "sha256:fff0000000000000000000000000000000000000000000000000000000000fff",
			},
		]}]},
	}}}

	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images information is missing",
	}}

	lib.assert_equal_results(base_image_registries.deny, expected) with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:fff0000000000000000000000000000000000000000000000000000000000fff"
		with lib.sbom.cyclonedx_sboms as []
		with lib.sbom.spdx_sboms as []

	lib.assert_equal_results(base_image_registries.deny, expected) with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa"
		with lib.sbom.cyclonedx_sboms as []
		with lib.sbom.spdx_sboms as []
}

test_allowed_registries_provided if {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
		"severity": "failure",
	}}
	lib.assert_equal_results(expected, base_image_registries.deny) with data.rule_data as {}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_rule_data_validation if {
	d := {"allowed_registry_prefixes": [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]}

	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

_spdx_sbom := [{"packages": [
	{
		# regal ignore:line-length
		"SPDXID": "SPDXRef-image-registry.redhat.io/single-container-app-9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
		"name": "single-container-app",
		"downloadLocation": "NOASSERTION",
		"externalRefs": [{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			# regal ignore:line-length
			"referenceLocator": "pkg:oci/single-container-app@sha256:abc0000000000000000000000000000000000000000000000000000000000abc?repository_url=registry.redhat.io/single-container-app",
		}],
		"annotations": [{
			"annotator": "Tool: konflux:jsonencoded",
			"comment": "{\"name\":\"konflux:container:is_base_image\",\"value\":\"true\"}",
			"annotationDate": "2024-12-09T12:00:00Z",
			"annotationType": "OTHER",
		}],
	},
	{
		# regal ignore:line-length
		"SPDXID": "SPDXRef-image-docker.io/single-container-app-9520a72cbb69edfca5cac88ea2a9e0e09142ec934952b9420d686e77765f002c",
		"name": "single-container-app",
		"downloadLocation": "NOASSERTION",
		"externalRefs": [{
			"referenceCategory": "PACKAGE-MANAGER",
			"referenceType": "purl",
			# regal ignore:line-length
			"referenceLocator": "pkg:oci/single-container-app@sha256:bcd0000000000000000000000000000000000000000000000000000000000bcd?repository_url=docker.io/single-container-app",
		}],
		"annotations": [{
			"annotator": "Tool: konflux:jsonencoded",
			"comment": "{\"name\":\"konflux:container:is_builder_image:for_stage\",\"value\":\"0\"}",
			"annotationDate": "2024-12-09T12:00:00Z",
			"annotationType": "OTHER",
		}],
	},
]}]
