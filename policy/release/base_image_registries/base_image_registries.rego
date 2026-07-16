#
# METADATA
# title: Base image checks
# description: >-
#   This package is responsible for verifying the base (parent) images
#   reported in the SLSA Provenace or the SBOM are allowed.
#
package base_image_registries

import rego.v1

import data.lib.image
import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data
import data.lib.sbom

# METADATA
# title: Base image comes from permitted registry
# description: >-
#   Verify that the base images used when building a container image are permitted.
#   Images can be permitted in three ways: by matching a registry prefix from
#   `allowed_registry_prefixes` rule data (deprecated), by matching a component digest
#   in the snapshot, or by having a valid release signature verified against the
#   `release_public_key` rule data. The preferred approach is signature-based
#   verification via `release_public_key`. Registry prefix matching is deprecated
#   and will be removed in a future release.
# custom:
#   short_name: base_image_permitted
#   failure_msg: Base image %q is from a disallowed registry
#   solution: >-
#     Make sure the image used in each task comes from a trusted registry. The list of
#     trusted registries is a configurable xref:cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - minimal
#   - redhat
#   - redhat_security
#   depends_on:
#   - base_image_registries.base_image_info_found
#   - base_image_registries.allowed_registries_provided
#
deny contains result if {
	some image_ref in _base_images
	not _image_ref_permitted(image_ref)
	repo := image.parse(image_ref).repo
	result := metadata.result_helper_with_term(rego.metadata.chain(), [image_ref], repo)
}

# METADATA
# title: Base images provided
# description: >-
#   Verify the expected information was provided about which base images were used during
#   the build process. The list of base images comes from any associated CycloneDX or SPDX
#   SBOMs.
# custom:
#   short_name: base_image_info_found
#   failure_msg: Base images information is missing
#   solution: >-
#     Ensure a CycloneDX SBOM is associated with the image.
#   collections:
#   - minimal
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	# Some images are built "from scratch" and not have any base images, e.g. UBI.
	# This check distinguishes such images by simply ensuring that at least one SBOM
	# is attached to the image.
	count(sbom.all_sboms) == 0

	result := metadata.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Allowed base image registry prefixes list or release public key was provided
# description: >-
#   Confirm that either the `allowed_registry_prefixes` or `release_public_key`
#   rule data was provided, since at least one is required by the policy rules
#   in this package.
# custom:
#   short_name: allowed_registries_provided
#   failure_msg: "%s"
#   solution: >-
#     Make sure to configure a list of trusted registries as a
#     xref:cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - minimal
#   - redhat
#   - policy_data
#   - redhat_security
#
deny contains result if {
	some error in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
}

# METADATA
# title: Registry prefix matching is deprecated
# description: >-
#   Using `allowed_registry_prefixes` to permit base images is deprecated.
#   Configure `release_public_key` to verify base image release signatures instead,
#   which provides stronger cryptographic assurance than registry prefix matching.
# custom:
#   short_name: registry_prefix_deprecated
#   failure_msg: >-
#     allowed_registry_prefixes is configured without release_public_key. Migrate
#     to signature-based verification by setting release_public_key in rule data.
#   solution: >-
#     Set the `release_public_key` in rule data to enable signature-based base image
#     verification. The key can be an inline PEM-encoded public key or a k8s://
#     reference to a secret containing the key.
#   collections:
#   - minimal
#   - redhat
#   - redhat_security
#
warn contains result if {
	prefixes := rule_data.get(_rule_data_key)
	count(prefixes) > 0
	not _release_public_key_provided
	result := metadata.result_helper(rego.metadata.chain(), [])
}

_image_ref_permitted(image_ref) if {
	allowed_prefixes := rule_data.get(_rule_data_key)
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
} else if {
	allowed_digests := {img.digest |
		some component in input.snapshot.components
		img := image.parse(component.containerImage)
	}
	image.parse(image_ref).digest in allowed_digests
} else if {
	key := rule_data.get(_release_key_rule_data_key)
	is_string(key)
	key != ""
	info := ec.sigstore.verify_image(image_ref, {"public_key": key, "ignore_rekor": false})
	not _has_sig_errors(info)
}

_has_sig_errors(info) if {
	some _ in info.errors
}

_release_public_key_provided if {
	key := rule_data.get(_release_key_rule_data_key)
	is_string(key)
	key != ""
}

_cyclonedx_base_images := [_cyclonedx_image_ref(component) |
	some s in sbom.cyclonedx_sboms
	some formulation in s.formulation
	some component in formulation.components
	component.type == "container"
	_is_cyclonedx_base_image(component)
]

_spdx_base_images := [_spdx_image_ref(pkg) |
	some s in sbom.spdx_sboms
	some pkg in s.packages
	_is_spdx_base_image(pkg)
]

_base_images := array.concat(_cyclonedx_base_images, _spdx_base_images)

# cyclonedx format
_is_cyclonedx_base_image(component) if {
	base_image_properties := [property |
		some property in component.properties
		_is_base_image_property(property)
	]
	count(base_image_properties) > 0
}

# spdx format
_is_spdx_base_image(pkg) if {
	base_image_properties := [property |
		some property in pkg.annotations
		_is_base_image_property(json.unmarshal(property.comment))
	]
	count(base_image_properties) > 0
}

_is_base_image_property(property) if {
	# Todo maybe: Make this less Konflux specific
	property.name == "konflux:container:is_base_image"
	value := property.value
	json.is_valid(value)
	json.unmarshal(value) == true
}

_is_base_image_property(property) if {
	# Todo maybe: Make this less Konflux specific
	property.name == "konflux:container:is_builder_image:for_stage"
	value := property.value
	json.is_valid(value)
	type_name(json.unmarshal(value)) == "number"
}

# Extract the image ref from the externalRef data in the SPDX package
_spdx_image_ref(pkg) := image_ref if {
	some ref in pkg.externalRefs
	ref.referenceType == "purl"
	image_ref := sbom.image_ref_from_purl(ref.referenceLocator)
}

# Extract the image ref from the purl in the CycloneDX component
_cyclonedx_image_ref(component) := image_ref if {
	purl := component.purl
	image_ref := sbom.image_ref_from_purl(purl)
}

_rule_data_errors contains error if {
	not _release_public_key_provided
	some e in j.validate_schema(
		rule_data.get(_rule_data_key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
			"minItems": 1,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	val := rule_data.get(_release_key_rule_data_key)
	val != []
	not is_string(val)
	msg := sprintf(
		"Rule data %s has unexpected format: expected a string, got %s",
		[_release_key_rule_data_key, type_name(val)],
	)
	error := {"message": msg, "severity": "failure"}
}

_rule_data_key := "allowed_registry_prefixes"

_release_key_rule_data_key := "release_public_key"
