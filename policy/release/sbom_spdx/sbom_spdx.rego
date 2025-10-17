#
# METADATA
# title: SPDX SBOM
# description: >-
#   Checks different properties of the CycloneDX SBOMs associated with the image being validated.
#
package sbom_spdx

import rego.v1

import data.lib
import data.lib.image
import data.lib.sbom

# METADATA
# title: Valid
# description: >-
#   Check the SPDX SBOM has the expected format. It verifies the SPDX SBOM matches the 2.3
#   version of the schema.
# custom:
#   short_name: valid
#   failure_msg: 'SPDX SBOM at index %d is not valid: %s'
#   solution: Make sure the build process produces a valid SPDX SBOM.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#
deny contains result if {
	some index, s in sbom.spdx_sboms
	some violation in json.match_schema(s, schema_2_3)[1]
	error := violation.error
	result := lib.result_helper(rego.metadata.chain(), [index, error])
}

# METADATA
# title: Contains packages
# description: Check the list of packages in the SPDX SBOM is not empty.
# custom:
#   short_name: contains_packages
#   failure_msg: The list of packages is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the package in the image.
#
deny contains result if {
	some s in sbom.spdx_sboms
	count(s.packages) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Allowed
# description: >-
#   Confirm the SPDX SBOM contains only allowed packages. By default all packages are allowed.
#   Use the "disallowed_packages" rule data key to provide a list of disallowed packages.
# custom:
#   short_name: allowed
#   failure_msg: "Package is not allowed: %s"
#   solution: >-
#     Update the image to not use any disallowed package.
#   collections:
#   - redhat
#   - redhat_rpms
#
deny contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages
	some ref in pkg.externalRefs
	ref.referenceType == "purl"
	sbom.has_item(ref.referenceLocator, lib.rule_data(sbom.rule_data_packages_key))
	result := lib.result_helper(rego.metadata.chain(), [ref.referenceLocator])
}

# METADATA
# title: Allowed package external references
# description: >-
#   Confirm the SPDX SBOM contains only packages with explicitly allowed
#   external references. By default all external references are allowed unless the
#   "allowed_external_references" rule data key provides a list of type-pattern pairs
#   that forbid the use of any other external reference of the given type where the
#   reference url matches the given pattern.
# custom:
#   short_name: allowed_package_external_references
#   failure_msg: Package %s has reference %q of type %q which is not explicitly allowed%s
#   solution: Update the image to use only packages with explicitly allowed external references.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages
	some reference in pkg.externalRefs
	some allowed in lib.rule_data(sbom.rule_data_allowed_external_references_key)
	reference.referenceType == allowed.type
	not regex.match(object.get(allowed, "url", ""), object.get(reference, "referenceLocator", ""))

	msg := regex.replace(object.get(allowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	# regal ignore:line-length
	result := lib.result_helper(rego.metadata.chain(), [pkg.name, reference.referenceLocator, reference.referenceType, msg])
}

# METADATA
# title: Disallowed package external references
# description: >-
#   Confirm the SPDX SBOM contains only packages without disallowed
#   external references. By default all external references are allowed. Use the
#   "disallowed_external_references" rule data key to provide a list of type-pattern pairs
#   that forbid the use of an external reference of the given type where the reference url
#   matches the given pattern.
# custom:
#   short_name: disallowed_package_external_references
#   failure_msg: Package %s has reference %q of type %q which is disallowed%s
#   solution: Update the image to not use a package with a disallowed external reference.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#   effective_on: 2024-07-31T00:00:00Z
deny contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages
	some reference in pkg.externalRefs
	some disallowed in lib.rule_data(sbom.rule_data_disallowed_external_references_key)

	reference.referenceType == disallowed.type
	regex.match(object.get(disallowed, "url", ""), object.get(reference, "referenceLocator", ""))

	msg := regex.replace(object.get(disallowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	# regal ignore:line-length
	result := lib.result_helper(rego.metadata.chain(), [pkg.name, reference.referenceLocator, reference.referenceType, msg])
}

# METADATA
# title: Contains files
# description: Check the list of files in the SPDX SBOM is not empty.
# custom:
#   short_name: contains_files
#   failure_msg: The list of files is empty
#   solution: >-
#     Verify the SBOM is correctly identifying the files in the image.
#
deny contains result if {
	some s in sbom.spdx_sboms
	count(s.files) == 0
	result := lib.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Matches image
# description: Check the SPDX SBOM targets the image being validated.
# custom:
#   short_name: matches_image
#   failure_msg: Image digest in the SBOM, %q, is not as expected, %q
#   solution: >-
#     The SPDX SBOM associated with the image describes a different image.
#     Verify the integrity of the build system.
#
deny contains result if {
	some s in sbom.spdx_sboms
	sbom_image := image.parse(s.name)
	expected_image := image.parse(input.image.ref)
	sbom_image.digest != expected_image.digest
	result := lib.result_helper(rego.metadata.chain(), [sbom_image.digest, expected_image.digest])
}

# METADATA
# title: Allowed package sources
# description: >-
#   For each of the packages fetched by Hermeto which define externalReferences,
#   verify they are allowed based on the allowed_package_sources rule data
#   key. By default, allowed_package_sources is empty, which means no components with such
#   references are allowed.
# custom:
#   short_name: allowed_package_sources
#   failure_msg: Package %s fetched by Hermeto was sourced from %q which is not allowed
#   solution: Update the image to not use a package from a disallowed source.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#   effective_on: 2025-02-17T00:00:00Z
deny contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages

	# only look at components fetched by Hermeto
	# cachi2 is kept here for backwards compatibility
	some annotation in pkg.annotations
	properties := json.unmarshal(annotation.comment)
	properties.name in {"hermeto:found_by", "cachi2:found_by"}
	properties.value in {"hermeto", "cachi2"}

	some externalref in pkg.externalRefs

	externalref.referenceType == "purl"

	purl := externalref.referenceLocator
	parsed_purl := ec.purl.parse(purl)

	# patterns are either those defined by the rule for a given purl type, or empty by default
	allowed_data := lib.rule_data(sbom.rule_data_allowed_package_sources_key)
	patterns := sbom.purl_allowed_patterns(parsed_purl.type, allowed_data)

	some qualifier in parsed_purl.qualifiers
	qualifier.key == "download_url"

	not sbom.url_matches_any_pattern(qualifier.value, patterns)

	result := lib.result_helper_with_term(rego.metadata.chain(), [purl, qualifier.value], purl)
}

# METADATA
# title: Disallowed package attributes
# description: >-
#   Confirm the SPDX SBOM contains only packages without disallowed
#   attributes. By default all attributes are allowed. Use the
#   "disallowed_attributes" rule data key to provide a list of key-value pairs
#   that forbid the use of an attribute set to the given value.
# custom:
#   short_name: disallowed_package_attributes
#   failure_msg: Package %s has the attribute %q set%s
#   solution: Update the image to not use any disallowed package attributes.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#   effective_on: 2025-02-04T00:00:00Z
deny contains result if {
	some s in sbom.spdx_sboms
	some pkg in s.packages

	some externalref in pkg.externalRefs

	some annotation in pkg.annotations
	properties := json.unmarshal(annotation.comment)
	some disallowed in lib.rule_data(sbom.rule_data_attributes_key)
	properties.name == disallowed.name

	object.get(properties, "value", "") == object.get(disallowed, "value", "")

	msg := regex.replace(object.get(properties, "value", ""), `(.+)`, ` to "$1"`)

	id := object.get(externalref, "referenceLocator", pkg.name)
	result := _with_effective_on(
		lib.result_helper_with_term(rego.metadata.chain(), [id, properties.name, msg], id),
		disallowed,
	)
}

# _with_effective_on annotates the result with the item's effective_on attribute. If the item does
# not have the attribute, result is returned unmodified.
_with_effective_on(result, item) := new_result if {
	new_result := object.union(result, {"effective_on": item.effective_on})
} else := result
