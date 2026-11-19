package base_image_registries_test

import rego.v1

import data.base_image_registries

import data.lib
import data.lib.assertions

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
			"purl": "pkg:oci/ubi@sha256:abc?repository_url=registry.redhat.io/ubi7",
		}]},
		{"components": [{
			"name": "registry",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
			"purl": "pkg:oci/registry@sha256:bcd?repository_url=docker.io/library/registry",
		}]},
	]}]

	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
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
			"purl": "pkg:oci/ubi@sha256:abc?repository_url=registry.redhat.io/ubi7",
		}]},
		{"components": [{
			"name": "registry",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
			"purl": "pkg:oci/registry@sha256:bcd?repository_url=docker.io/library/registry",
		}]},
	]}]

	snapshot := {"components": [
		{"containerImage": "ignored.io/ignore@sha256:abc"},
		{"containerImage": "ignored.dev/ignore:ignore@sha256:bcd"},
	]}

	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as _spdx_sbom
		with data.rule_data.allowed_registry_prefixes as ["another.registry.io"]
		with input.snapshot as snapshot
}

test_empty_base_images_result if {
	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as [{}] with lib.sbom.spdx_sboms as [{}]
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
		{"op": "replace", "path": "/0/packages/0/externalRefs/0/referenceLocator", "value": "pkg:oci/ignored@sha256:123?repository_url=registry.redhat.blah/ubi7/3"},
		# regal ignore:line-length
		{"op": "replace", "path": "/0/packages/1/externalRefs/0/referenceLocator", "value": "pkg:oci/ignored@sha256:456?repository_url=registry.redhat.whatever/ubi7/3"},
		# Actually these two won't matter, but let's change them anyhow so the name and repository_url are consistent
		{"op": "replace", "path": "/0/packages/0/name", "value": "registry.redhat.blah/ubi7/3"},
		{"op": "replace", "path": "/0/packages/1/name", "value": "registry.redhat.whatever/ubi7/3"},
	])

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.yo/ubi7/3@sha256:6123\" is not permitted",
			"term": "registry.redhat.yo/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.ioo/spam/3@sha256:6123\" is not permitted",
			"term": "registry.redhat.ioo/spam/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"dockery.io/busybox/3@sha256:6123\" is not permitted",
			"term": "dockery.io/busybox/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.blah/ubi7/3@sha256:123\" is not permitted",
			"term": "registry.redhat.blah/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.whatever/ubi7/3@sha256:456\" is not permitted",
			"term": "registry.redhat.whatever/ubi7/3",
		},
	}
	assertions.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as bad_spdx_sbom
		with ec.sigstore.verify_image as {"success": false, "errors": []}
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
			"purl": "pkg:oci/ubi@sha256:abc?repository_url=registry.redhat.io/ubi7",
		}]},
		{"components": [{
			"name": "registry",
			"type": "container",
			"properties": [{
				"name": "konflux:container:is_builder_image:for_stage",
				"value": "0",
			}],
			"purl": "pkg:oci/registry@sha256:bcd?repository_url=docker.io/library/registry",
		}]},
	]}]

	bad_spdx_sbom := json.patch(_spdx_sbom, [
		# Tweak the repository_url so they're no longer allowed
		# regal ignore:line-length
		{"op": "replace", "path": "/0/packages/0/externalRefs/0/referenceLocator", "value": "pkg:oci/3@sha256:ccc?repository_url=registry.redhat.blah/ubi7/3"},
		# regal ignore:line-length
		{"op": "replace", "path": "/0/packages/1/externalRefs/0/referenceLocator", "value": "pkg:oci/3@sha256:ddd?repository_url=registry.redhat.whatever/ubi7/3"},
		# Actually these two won't matter, but let's change them anyhow so the name and repository_url are consistent
		{"op": "replace", "path": "/0/packages/0/name", "value": "3"},
		{"op": "replace", "path": "/0/packages/1/name", "value": "3"},
	])

	snapshot := {"components": [
		{"containerImage": "ignored.io/ignore@sha256:cba"},
		{"containerImage": "ignored.dev/ignore:ignore@sha256:dcb"},
	]}

	expected := {
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"docker.io/library/registry@sha256:bcd\" is not permitted",
			"term": "docker.io/library/registry",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.io/ubi7@sha256:abc\" is not permitted",
			"term": "registry.redhat.io/ubi7",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.blah/ubi7/3@sha256:ccc\" is not permitted",
			"term": "registry.redhat.blah/ubi7/3",
		},
		{
			"code": "base_image_registries.base_image_permitted",
			"msg": "Base image \"registry.redhat.whatever/ubi7/3@sha256:ddd\" is not permitted",
			"term": "registry.redhat.whatever/ubi7/3",
		},
	}

	assertions.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as bad_spdx_sbom
		with data.rule_data.allowed_registry_prefixes as ["another.registry.io"]
		with input.snapshot as snapshot
		with ec.sigstore.verify_image as {"success": false, "errors": []}
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

	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as []
}

test_base_image_not_found if {
	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images information is missing",
	}}
	assertions.assert_equal_results(base_image_registries.deny, expected)
}

test_base_image_not_found_image_index if {
	att := {"statement": {"predicate": {
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
	}}}

	expected := {{
		"code": "base_image_registries.base_image_info_found",
		"msg": "Base images information is missing",
	}}

	assertions.assert_equal_results(base_image_registries.deny, expected) with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:fff0000000000000000000000000000000000000000000000000000000000fff"
		with lib.sbom.cyclonedx_sboms as []
		with lib.sbom.spdx_sboms as []

	assertions.assert_equal_results(base_image_registries.deny, expected) with input.attestations as [att]
		with input.image.ref as "registry.local/ham@sha256:aaa0000000000000000000000000000000000000000000000000000000000aaa"
		with lib.sbom.cyclonedx_sboms as []
		with lib.sbom.spdx_sboms as []
}

test_allowed_registries_provided if {
	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(expected, base_image_registries.deny) with data.rule_data as {}
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
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "allowed_registry_prefixes is configured without signing_identities. Migrate to signature-based verification by setting signing_identities in rule data.",
			"severity": "warning",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

# RA07-BASE-DATA-SCALAR-001: a present but scalar `allowed_registry_prefixes` value must produce
# a format rejection from the v2 rule instead of silently skipping the check. The legacy
# allowed_registries_provided is untouched: a builtin error in its schema validation still
# suppresses its result, which is the gap the v2 rule closes.
test_allowed_registries_provided_v2_scalar_rejected if {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided_v2",
		"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as {"allowed_registry_prefixes": 1}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

# A non-JSON string value is rejected by the v2 rule only: the legacy rule is
# silent because json.match_schema fails to parse the string as serialized
# JSON, which suppresses its result.
test_allowed_registries_provided_v2_string_rejected if {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided_v2",
		"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
		"severity": "failure",
	}}
	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as {"allowed_registry_prefixes": "x"}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

# A string containing JSON text for an array must not be mistaken for a
# native array. The legacy rule parses it as an empty array and reports only
# the container-level minItems diagnostic; the v2 rule reports the actual
# string type.
test_allowed_registries_provided_v2_json_text_string_rejected if {
	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: string",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as {"allowed_registry_prefixes": "[]"}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

# A malformed high-priority override must be rejected rather than silently
# falling back to valid lower-priority data.
test_allowed_registries_provided_v2_precedence if {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided_v2",
		"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: integer",
		"severity": "failure",
	}}
	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data_custom as {"allowed_registry_prefixes": 1}
		with data.rule_data as {"allowed_registry_prefixes": ["registry.redhat.io/"]}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

# Shape controls locking in the current format contract: null and wrong-container values are
# rejected by both rules with identical messages.
test_allowed_registries_null_rejected if {
	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: Provided empty document for schema validation",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as {"allowed_registry_prefixes": null}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_allowed_registries_wrong_container_rejected if {
	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): Invalid type. Expected: array, given: object",
			"severity": "failure",
		},
	}
	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as {"allowed_registry_prefixes": {"foo": "bar"}}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

# The baseline permits an empty prefix list when the signing-identity condition allows it:
# with a valid rh-release identity the minimum list length is zero and an explicit empty
# array is schema-valid.
test_allowed_registries_empty_array_valid_with_signing_identity if {
	assertions.assert_empty(base_image_registries.deny) with data.rule_data as {
		"signing_identities": {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}},
		"allowed_registry_prefixes": [],
	}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_signature_verified_base_image if {
	sboms := [{"formulation": [{"components": [{
		"name": "ubi",
		"type": "container",
		"properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
		"purl": "pkg:oci/ubi@sha256:abc?repository_url=unknown.registry.io/ubi",
	}]}]}]

	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as []
		with data.rule_data.allowed_registry_prefixes as ["other.registry.io/"]
		with data.rule_data.signing_identities as {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}}
		with ec.sigstore.verify_image as {"success": true, "errors": []}
}

test_signature_verification_failed if {
	sboms := [{"formulation": [{"components": [{
		"name": "ubi",
		"type": "container",
		"properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
		"purl": "pkg:oci/ubi@sha256:abc?repository_url=unknown.registry.io/ubi",
	}]}]}]

	expected := {{
		"code": "base_image_registries.base_image_permitted",
		# regal ignore:line-length
		"msg": "Base image \"unknown.registry.io/ubi@sha256:abc\" is not permitted",
		"term": "unknown.registry.io/ubi",
	}}

	assertions.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as []
		with data.rule_data.allowed_registry_prefixes as ["other.registry.io/"]
		with data.rule_data.signing_identities as {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}}
		with ec.sigstore.verify_image as {"success": false, "errors": ["signature verification failed"]}
}

test_no_release_key_is_noop if {
	sboms := [{"formulation": [{"components": [{
		"name": "ubi",
		"type": "container",
		"properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
		"purl": "pkg:oci/ubi@sha256:abc?repository_url=registry.redhat.io/ubi",
	}]}]}]

	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		# regal ignore:line-length
		"msg": "allowed_registry_prefixes is configured without signing_identities. Migrate to signature-based verification by setting signing_identities in rule data.",
		"severity": "warning",
	}}

	assertions.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as []
		with data.rule_data as {"allowed_registry_prefixes": ["registry.redhat.io/"]}
}

test_allowed_with_only_release_key if {
	sboms := [{"formulation": [{"components": [{
		"name": "ubi",
		"type": "container",
		"properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
		"purl": "pkg:oci/ubi@sha256:abc?repository_url=unknown.registry.io/ubi",
	}]}]}]

	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as []
		with data.rule_data as {"signing_identities": {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}}}
		with ec.sigstore.verify_image as {"success": true, "errors": []}
}

test_deprecation_warning_registry_prefixes_without_key if {
	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		# regal ignore:line-length
		"msg": "allowed_registry_prefixes is configured without signing_identities. Migrate to signature-based verification by setting signing_identities in rule data.",
		"severity": "warning",
	}}

	d := {"allowed_registry_prefixes": ["registry.redhat.io/"]}

	assertions.assert_equal_results(base_image_registries.deny, expected) with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
		with data.rule_data as d
}

test_no_deprecation_warning_with_signing_identity if {
	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
		with data.rule_data.signing_identities as {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}}
}

test_no_deprecation_warning_without_prefixes if {
	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
		with data.rule_data as {"signing_identities": {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}}}
}

test_signing_identities_validation if {
	d := {
		"signing_identities": 42,
		"allowed_registry_prefixes": ["registry.redhat.io/"],
	}

	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "Rule data signing_identities has unexpected format: expected an object, got number",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "allowed_registry_prefixes is configured without signing_identities. Migrate to signature-based verification by setting signing_identities in rule data.",
			"severity": "warning",
		},
	}

	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_signing_identity_entry_validation if {
	d := {
		"signing_identities": {"rh-release": "not-an-object"},
		"allowed_registry_prefixes": ["registry.redhat.io/"],
	}

	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		# regal ignore:line-length
		"msg": "Rule data signing_identities.rh-release has unexpected format: expected an object, got string",
		"severity": "failure",
	}}

	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_signing_identity_validation_integration if {
	d := {"signing_identities": {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH..."}}}

	expected := {{
		"code": "base_image_registries.allowed_registries_provided",
		# regal ignore:line-length
		"msg": "Rule data signing_identities.rh-release requires rekor_url, rekor_public_key, or ignore_rekor when using public_key verification",
		"severity": "failure",
	}}

	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_opts_passed_directly_from_rule_data if {
	sboms := [{"formulation": [{"components": [{
		"name": "ubi",
		"type": "container",
		"properties": [{"name": "konflux:container:is_base_image", "value": "true"}],
		"purl": "pkg:oci/ubi@sha256:abc?repository_url=unknown.registry.io/ubi",
	}]}]}]

	signing_identity := {
		"public_key": "k8s://openshift-pipelines/release-signing-key",
		"ignore_rekor": true,
	}

	assertions.assert_empty(base_image_registries.deny) with lib.sbom.cyclonedx_sboms as sboms
		with lib.sbom.spdx_sboms as []
		with data.rule_data as {"signing_identities": {"rh-release": signing_identity}}
		with ec.sigstore.verify_image as _mock_verify_opts_match
}

test_allowed_registries_provided_with_signing_identity if {
	assertions.assert_empty(base_image_registries.deny) with data.rule_data as {"signing_identities": {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}}}
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_prefix_validation_with_signing_identity if {
	d := {
		"signing_identities": {"rh-release": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}},
		"allowed_registry_prefixes": [1, "foo", "foo"],
	}

	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "base_image_registries.allowed_registries_provided_v2",
			# regal ignore:line-length
			"msg": "Rule data allowed_registry_prefixes has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

test_signing_identities_missing_expected_key if {
	d := {
		"signing_identities": {"wrong-name": {"public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...", "ignore_rekor": true}},
		"allowed_registry_prefixes": ["registry.redhat.io/"],
	}

	expected := {
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "Rule data signing_identities does not contain the expected key \"rh-release\"",
			"severity": "warning",
		},
		{
			"code": "base_image_registries.allowed_registries_provided",
			# regal ignore:line-length
			"msg": "allowed_registry_prefixes is configured without signing_identities. Migrate to signature-based verification by setting signing_identities in rule data.",
			"severity": "warning",
		},
	}

	assertions.assert_equal_results(base_image_registries.deny, expected) with data.rule_data as d
		with lib.sbom.cyclonedx_sboms as [{}]
		with lib.sbom.spdx_sboms as [{}]
}

_mock_verify_opts_match(_, opts) := {"success": true, "errors": []} if {
	opts.public_key == "k8s://openshift-pipelines/release-signing-key"
	opts.ignore_rekor == true
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
			"referenceLocator": "pkg:oci/single-container-app@sha256:abc?repository_url=registry.redhat.io/single-container-app",
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
			"referenceLocator": "pkg:oci/single-container-app@sha256:bcd?repository_url=docker.io/single-container-app",
		}],
		"annotations": [{
			"annotator": "Tool: konflux:jsonencoded",
			"comment": "{\"name\":\"konflux:container:is_builder_image:for_stage\",\"value\":\"0\"}",
			"annotationDate": "2024-12-09T12:00:00Z",
			"annotationType": "OTHER",
		}],
	},
]}]
