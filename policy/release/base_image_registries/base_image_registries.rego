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
import data.lib.sigstore

# METADATA
# title: Base image is permitted
# description: >-
#   Verify that the base images used when building a container image are permitted.
#   Images can be permitted in three ways: by having a valid signature
#   verified against the `rh-release` entry in `signing_identities` rule data
#   (preferred), by matching a component digest in the snapshot, or by matching
#   a registry prefix from `allowed_registry_prefixes` rule data (deprecated).
#   Registry prefix matching is deprecated and will be removed in a future release.
# custom:
#   short_name: base_image_permitted
#   failure_msg: Base image %q is not permitted
#   solution: >-
#     Make sure the base image is permitted by one of the following methods (in order
#     of preference): configure a signing identity under the `rh-release` key in the
#     `signing_identities` xref:signing_identities.adoc#_signing_identities_structure[configuration]
#     so the image signature can be verified, ensure the image digest matches a component
#     in the snapshot, or add the image registry to the `allowed_registry_prefixes` data
#     source (deprecated).
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
# title: Allowed base image registry prefixes list or signing identity was provided
# description: >-
#   Confirm that either the `allowed_registry_prefixes` or a `signing_identities`
#   entry was provided, since at least one is required by the policy rules
#   in this package.
# custom:
#   short_name: allowed_registries_provided
#   failure_msg: "%s"
#   solution: >-
#     Make sure to configure either a signing identity under the `rh-release` key in
#     the `signing_identities` xref:signing_identities.adoc#_signing_identities_structure[configuration]
#     or a list of trusted registry prefixes in `allowed_registry_prefixes`.
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
# title: Allowed base image registry prefixes list or signing identity was provided (v2)
# description: >-
#   Confirm that either the `allowed_registry_prefixes` or a `signing_identities`
#   entry was provided, since at least one is required by the policy rules
#   in this package. Unlike allowed_registries_provided, a present value of the
#   wrong type (for example a scalar or a string containing JSON text) is rejected
#   instead of silently skipping the check.
# custom:
#   short_name: allowed_registries_provided_v2
#   failure_msg: "%s"
#   solution: >-
#     Make sure to configure either a signing identity under the `rh-release` key in
#     the `signing_identities` xref:signing_identities.adoc#_signing_identities_structure[configuration]
#     or a list of trusted registry prefixes in `allowed_registry_prefixes`.
#   collections:
#   - minimal
#   - redhat
#   - policy_data
#   - redhat_security
#   effective_on: 2027-01-11T00:00:00Z
#
deny contains result if {
	some error in _rule_data_errors_v2
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [error.message], error.severity)
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
	info := ec.sigstore.verify_image(image_ref, _signing_identity)
	object.get(info, "success", false) == true
}

_signing_identity := sigstore.named_identity(_signing_identity_name)

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
	some e in j.validate_schema(rule_data.get(_rule_data_key), _rule_data_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_errors contains error if {
	prefixes := rule_data.get(_rule_data_key)
	is_array(prefixes)
	count(prefixes) > 0
	not _signing_identity
	error := {
		# regal ignore:line-length
		"message": "allowed_registry_prefixes is configured without signing_identities. Migrate to signature-based verification by setting signing_identities in rule data.",
		"severity": "warning",
	}
}

# Validate the signing_identities rule data for the rh-release identity via the
# shared sigstore helper. rh-release is expected to be present, so this includes
# the "missing expected key" warning (map shape, entry shape, verification
# config, and presence).
_rule_data_errors contains error if {
	some error in sigstore.identity_rule_data_errors(_signing_identity_name)
}

# _rule_data_errors_v2 mirrors the schema-based _rule_data_errors rule for
# `allowed_registry_prefixes` but validates the value as native rule data: a present
# scalar value is reported as a format violation instead of raising a builtin error that
# suppresses the result, and a string is never interpreted as serialized JSON. The
# signing-identity and deprecation diagnostics stay on the legacy rule only.
_rule_data_errors_v2 contains error if {
	some e in j.validate_schema_native(rule_data.get(_rule_data_key), _rule_data_schema)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [_rule_data_key, e.message]),
		"severity": e.severity,
	}
}

_rule_data_schema := {
	"$schema": "http://json-schema.org/draft-07/schema#",
	"type": "array",
	"items": {"type": "string"},
	"uniqueItems": true,
	"minItems": _prefixes_min_items,
}

_rule_data_key := "allowed_registry_prefixes"

_signing_identity_name := "rh-release"

default _prefixes_min_items := 1

_prefixes_min_items := 0 if {
	is_object(_signing_identity)
}
