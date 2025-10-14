#
# METADATA
# title: SBOM CycloneDX
# description: >-
#   Checks different properties of the CycloneDX SBOMs associated with the image being validated.
#
package sbom_cyclonedx

import rego.v1

import data.lib
import data.lib.sbom

# METADATA
# title: Valid
# description: >-
#   Check the CycloneDX SBOM has the expected format. It verifies the CycloneDX SBOM matches the 1.5
#   version of the schema.
# custom:
#   short_name: valid
#   failure_msg: 'CycloneDX SBOM at index %d is not valid: %s'
#   solution: Make sure the build process produces a valid CycloneDX SBOM.
#   collections:
#   - minimal
#   - redhat
#   - redhat_rpms
#
deny contains result if {
	some index, s in sbom.cyclonedx_sboms
	some violation in json.match_schema(s, schema_1_5)[1]
	error := violation.error
	result := lib.result_helper(rego.metadata.chain(), [index, error])
}

# METADATA
# title: Allowed
# description: >-
#   Confirm the CycloneDX SBOM contains only allowed packages. By default all packages are allowed.
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
	some s in sbom.cyclonedx_sboms
	some component in s.components
	sbom.has_item(component.purl, lib.rule_data(sbom.rule_data_packages_key))
	result := lib.result_helper(rego.metadata.chain(), [component.purl])
}

# METADATA
# title: Disallowed package attributes
# description: >-
#   Confirm the CycloneDX SBOM contains only packages without disallowed
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
#   effective_on: 2024-07-31T00:00:00Z
deny contains result if {
	some s in sbom.cyclonedx_sboms
	some component in s.components
	some property in component.properties
	some disallowed in lib.rule_data(sbom.rule_data_attributes_key)

	property.name == disallowed.name
	object.get(property, "value", "") == object.get(disallowed, "value", "")

	msg := regex.replace(object.get(property, "value", ""), `(.+)`, ` to "$1"`)

	id := object.get(component, "purl", component.name)
	result := _with_effective_on(
		lib.result_helper_with_term(rego.metadata.chain(), [id, property.name, msg], id),
		disallowed,
	)
}

# METADATA
# title: Allowed package external references
# description: >-
#   Confirm the CycloneDX SBOM contains only packages with explicitly allowed
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
	some s in sbom.cyclonedx_sboms
	some component in s.components
	some reference in component.externalReferences
	some allowed in lib.rule_data(sbom.rule_data_allowed_external_references_key)

	reference.type == allowed.type
	not regex.match(object.get(allowed, "url", ""), object.get(reference, "url", ""))

	msg := regex.replace(object.get(allowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	id := object.get(component, "purl", component.name)
	result := lib.result_helper_with_term(rego.metadata.chain(), [id, reference.url, reference.type, msg], id)
}

# METADATA
# title: Disallowed package external references
# description: >-
#   Confirm the CycloneDX SBOM contains only packages without disallowed
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
	some s in sbom.cyclonedx_sboms
	some component in s.components
	some reference in component.externalReferences
	some disallowed in lib.rule_data(sbom.rule_data_disallowed_external_references_key)

	reference.type == disallowed.type
	regex.match(object.get(disallowed, "url", ""), object.get(reference, "url", ""))

	msg := regex.replace(object.get(disallowed, "url", ""), `(.+)`, ` by pattern "$1"`)

	id := object.get(component, "purl", component.name)
	result := lib.result_helper_with_term(rego.metadata.chain(), [id, reference.url, reference.type, msg], id)
}

# METADATA
# title: Allowed package sources
# description: >-
#   For each of the components fetched by Hermeto which define externalReferences of type
#   distribution, verify they are allowed based on the allowed_package_sources rule data
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
#   effective_on: 2024-12-15T00:00:00Z
deny contains result if {
	some s in sbom.cyclonedx_sboms
	some component in s.components

	# only look at components that define an externalReferences of type `distribution`
	some reference in component.externalReferences
	reference.type == "distribution"

	# only look at components fetched by Hermeto
	# cachi2 is kept here for backwards compatibility
	some properties in component.properties
	properties.name in {"hermeto:found_by", "cachi2:found_by"}
	properties.value in {"hermeto", "cachi2"}

	purl := component.purl
	parsed_purl := ec.purl.parse(purl)

	# patterns are either those defined by the rule for a given purl type, or empty by default
	allowed_data := lib.rule_data(sbom.rule_data_allowed_package_sources_key)
	patterns := sbom.purl_allowed_patterns(parsed_purl.type, allowed_data)
	distribution_url := object.get(reference, "url", "")

	# only progress past this point if no matches were found
	not sbom.url_matches_any_pattern(distribution_url, patterns)

	result := lib.result_helper_with_term(rego.metadata.chain(), [purl, distribution_url], purl)
}

# _with_effective_on annotates the result with the item's effective_on attribute. If the item does
# not have the attribute, result is returned unmodified.
_with_effective_on(result, item) := new_result if {
	new_result := object.union(result, {"effective_on": item.effective_on})
} else := result
