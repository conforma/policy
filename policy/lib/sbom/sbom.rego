package lib.sbom

import data.lib
import data.lib.rule_data

import data.lib.image
import data.lib.json as j
import data.lib.oci
import data.lib.tekton
import rego.v1

# cyclonedx_sboms and spdx_sboms returns a list of SBOMs associated with the image being validated.
# It will first try to find them as references in the SLSA Provenance attestation and as an SBOM
# attestation.

_sbom_artifact_types := {
	"application/spdx+json",
	"application/vnd.cyclonedx+json",
}

all_sboms := array.concat(cyclonedx_sboms, spdx_sboms)

cyclonedx_sboms := [s | some s in _cyclonedx_sboms]

spdx_sboms := [s | some s in _spdx_sboms]

# Private set rules for deduplication. Sets naturally eliminate duplicates when the
# same SBOM is discovered via multiple methods (attestation, OCI blob, referrer, tag).
_cyclonedx_sboms := (_cyclonedx_sboms_from_input | _cyclonedx_sboms_from_pipelinerun) | _cyclonedx_sboms_from_image
_spdx_sboms := (_spdx_sboms_from_input | _spdx_sboms_from_pipelinerun) | _spdx_sboms_from_image

_cyclonedx_sboms_from_input contains statement.predicate if {
	some att in input.attestations
	statement := att.statement

	# https://cyclonedx.org/specification/overview/#recognized-predicate-type
	statement.predicateType == "https://cyclonedx.org/bom"
}

_cyclonedx_sboms_from_pipelinerun contains sbom if {
	some sbom in _fetch_pipelinerun_sbom
	sbom.bomFormat == "CycloneDX"
}

_cyclonedx_sboms_from_image contains sbom if {
	some sbom in _fetch_sboms_from_image
	sbom.bomFormat == "CycloneDX"
}

_spdx_sboms_from_input contains statement.predicate if {
	some att in input.attestations
	statement := att.statement
	statement.predicateType == "https://spdx.dev/Document"
}

_spdx_sboms_from_pipelinerun contains sbom if {
	some sbom in _fetch_pipelinerun_sbom
	sbom.SPDXID == "SPDXRef-DOCUMENT"
}

_spdx_sboms_from_image contains sbom if {
	some sbom in _fetch_sboms_from_image
	sbom.SPDXID == "SPDXRef-DOCUMENT"
}

_fetch_pipelinerun_sbom contains sbom if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.build_tasks(attestation)

	# For multi-platform images, the same SLSA Provenance may describe all the platform specific
	# images. Each will have its own SBOM. Only select the SBOM for the image being evaluated.
	expected_image_digest := image.parse(input.image.ref).digest
	image_digest := tekton.task_result(task, "IMAGE_DIGEST")
	expected_image_digest == image_digest

	blob_ref := tekton.task_result(task, "SBOM_BLOB_URL")
	blob := ec.oci.blob(blob_ref)
	sbom := json.unmarshal(blob)
}

# _fetch_sboms_from_image discovers SBOMs attached directly to the image being validated,
# using the OCI Referrers API and legacy tag-based discovery.
_fetch_sboms_from_image := _sboms_from_referrers | _sboms_from_tag_refs

# Discover SBOMs via OCI Referrers API. Referrers with recognized SBOM artifact types
# have their content fetched and parsed.
_sboms_from_referrers contains sbom if {
	some referrer in ec.oci.image_referrers(input.image.ref)
	referrer.artifactType in _sbom_artifact_types
	blob := ec.oci.blob(referrer.ref)
	sbom := json.unmarshal(blob)
}

# Discover SBOMs via legacy cosign tag-based conventions (.sbom suffix).
# Tag refs point to OCI images, so we fetch the manifest and extract the
# blob from its first layer using blob_from_image.
_sboms_from_tag_refs contains sbom if {
	some ref in ec.oci.image_tag_refs(input.image.ref)
	endswith(ref, ".sbom")
	blob := oci.blob_from_image(ref)
	sbom := json.unmarshal(blob)
}

has_item(needle, haystack) if {
	needle_purl := ec.purl.parse(needle)

	some hay in haystack
	hay_purl := ec.purl.parse(hay.purl)

	needle_purl.type == hay_purl.type
	needle_purl.namespace == hay_purl.namespace
	needle_purl.name == hay_purl.name
	_matches_version(needle_purl.version, hay)

	not _excluded(needle_purl, object.get(hay, "exceptions", []))
} else := false

_excluded(purl, exceptions) if {
	matches := [exception |
		some exception in exceptions
		exception.subpath == purl.subpath
	]
	count(matches) > 0
}

_matches_version(version, matcher) if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	matcher.max != ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.min != ""
	object.get(matcher, "max", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.min)) != -1
} else if {
	matcher.format in {"semverv", "semver"}
	matcher.max != ""
	object.get(matcher, "min", "") == ""
	semver.compare(_to_semver(version), _to_semver(matcher.max)) != 1
} else := false

_to_semver(v) := trim_prefix(v, "v")

# get allowed pattens for given purl type, or empty list if not defined
purl_allowed_patterns(purl_type, allowed_rule_data) := patterns if {
	some allowed in allowed_rule_data
	purl_type == allowed.type
	patterns := allowed.patterns
} else := []

# see if any pattern matches given url
url_matches_any_pattern(url, patterns) if {
	some pattern in patterns
	regex.match(pattern, url)
}

image_ref_from_purl(raw_purl) := image_ref if {
	# Example purl:
	#   "pkg:oci/someapp@sha256:012abc?repository_url=someregistry.io/someorg/someapp"
	purl := ec.purl.parse(raw_purl)
	purl.type == "oci"

	# Todo maybe: We see "oci" in SBOMs produced by Konflux, but I think
	# other SPDX creators might reasonably use "pkg:docker/" in the purl.
	# purl.type in {"oci", "docker"}

	# Example image_digest: "sha256:012abc0000000000000000000000000000000000000000000000000000012abc"
	image_digest := purl.version

	some qualifier in purl.qualifiers
	qualifier.key == "repository_url"

	# Example repo_url: "someregistry.io/someorg/someapp"
	# It's probably the same as pkg.name, but let's use the value from the purl
	repo_url := qualifier.value

	# Put them together to make a pinned image_ref
	image_ref := sprintf("%s@%s", [repo_url, image_digest])
}

# Verify disallowed_packages is an array of objects
rule_data_errors contains error if {
	some e in j.validate_schema(rule_data.get(rule_data_packages_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"purl": {"type": "string"},
				"format": {"enum": ["semver", "semverv"]},
				"min": {"type": "string"},
				"max": {"type": "string"},
				"exceptions": {
					"type": "array",
					"uniqueItems": true,
					"items": {
						"type": "object",
						"properties": {"subpath": {"type": "string"}},
					},
				},
			},
			"additionalProperties": false,
			"anyOf": [
				{"required": ["purl", "format", "min"]},
				{"required": ["purl", "format", "max"]},
			],
		},
	})
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_packages_key, e.message]),
		"severity": e.severity,
	}
}

# Verify each item in disallowed_packages has a parseable PURL
rule_data_errors contains error if {
	some index, pkg in rule_data.get(rule_data_packages_key)
	purl := pkg.purl
	not ec.purl.is_valid(purl)
	error := {
		"message": sprintf("Item at index %d in %s does not have a valid PURL: %q", [index, rule_data_packages_key, purl]),
		"severity": "failure",
	}
}

# Verify each item in disallowed_packages has a parseable min/max semver
rule_data_errors contains error if {
	some index, pkg in rule_data.get(rule_data_packages_key)
	pkg.format in {"semver", "semverv"}
	some attr in ["min", "max"]

	version := _to_semver(object.get(pkg, attr, ""))
	version != ""

	not semver.is_valid(version)

	error := {
		"message": sprintf(
			"Item at index %d in %s does not have a valid %s semver value: %q",
			[index, rule_data_packages_key, attr, version],
		),
		"severity": "failure",
	}
}

# Verify disallowed_attributes is an array of name value pairs
rule_data_errors contains error if {
	some e in j.validate_schema(rule_data.get(rule_data_attributes_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"name": {"type": "string"},
				"value": {"type": "string"},
				"effective_on": {"type": "string", "format": "date-time"},
			},
			"additionalProperties": false,
			"required": ["name"],
		},
	})
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_attributes_key, e.message]),
		"severity": e.severity,
	}
}

# Verify allowed_external_references is an array of type/url pairs
rule_data_errors contains error if {
	some e in j.validate_schema(rule_data.get(rule_data_allowed_external_references_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"type": {"type": "string"},
				"url": {"type": "string"},
			},
			"additionalProperties": false,
			"required": ["type", "url"],
		},
	})
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_allowed_external_references_key, e.message]),
		"severity": e.severity,
	}
}

# Verify disallowed_external_references is an array of type/url pairs
rule_data_errors contains error if {
	some e in j.validate_schema(rule_data.get(rule_data_disallowed_external_references_key), {
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "array",
		"uniqueItems": true,
		"items": {
			"type": "object",
			"properties": {
				"type": {"type": "string"},
				"url": {"type": "string"},
			},
			"additionalProperties": false,
			"required": ["type", "url"],
		},
	})

	error := {
		# regal ignore:line-length
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_disallowed_external_references_key, e.message]),
		"severity": e.severity,
	}
}

# Verify allowed_package_sources is array of purl/regex list pairs
rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get(rule_data_allowed_package_sources_key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {
				"type": "object",
				"properties": {
					"type": {"type": "string"},
					"patterns": {
						"type": "array",
						"items": {
							"type": "string",
							"format": "regex",
						},
					},
				},
				"required": ["type", "patterns"],
				"additionalProperties": false,
			},
		},
	)

	error := {
		# regal ignore:line-length
		"message": sprintf("Rule data %s has unexpected format: %s", [rule_data_allowed_package_sources_key, e.message]),
		"severity": e.severity,
	}
}

# Verify proxy_enabled_purl_types is a list of unique strings.
rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("proxy_enabled_purl_types"),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
		},
	)
	error := {
		"message": sprintf("Rule data proxy_enabled_purl_types has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

# Verify allowed_proxy_url_patterns is an object mapping strings to arrays of strings.
rule_data_errors contains error if {
	some e in j.validate_schema(
		rule_data.get("allowed_proxy_url_patterns"),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "object",
			"additionalProperties": {
				"type": "array",
				"items": {"type": "string"},
				"uniqueItems": true,
			},
		},
	)
	error := {
		"message": sprintf("Rule data allowed_proxy_url_patterns has unexpected format: %s", [e.message]),
		"severity": e.severity,
	}
}

# Verify items in allowed_proxy_url_patterns are valid regular expressions.
rule_data_errors contains error if {
	some purl_type, patterns in rule_data.get("allowed_proxy_url_patterns")
	some pattern in patterns
	not regex.is_valid(pattern)
	error := {
		"message": sprintf("%q is not a valid regular expression for PURL type %q", [pattern, purl_type]),
		"severity": "failure",
	}
}

# component_found_by_hermeto checks if a CycloneDX component was fetched by
# cachi2 or hermeto, based on the component's properties.
component_found_by_hermeto(component) if {
	some property in component.properties
	some name in _hermeto_names
	property == _hermeto_found_by_property(name)
} else := false

# package_found_by_hermeto checks if an SPDX package was fetched by
# cachi2 or hermeto, based on the package's annotations.
package_found_by_hermeto(pkg) if {
	some annotation in pkg.annotations
	some name in _hermeto_names
	regex.match(sprintf(`.*%s.*`, [name]), annotation.annotator)
	annotation.annotationType == "OTHER"
} else := false

# is_registry_dependency returns true if the parsed PURL has no download_url
# or vcs_url qualifier, indicating it is a registry dependency.
is_registry_dependency(parsed_purl) if {
	qualifiers := {q.key | some q in object.get(parsed_purl, "qualifiers", [])}
	not "download_url" in qualifiers
	not "vcs_url" in qualifiers
}

# hermeto_found_by_property generates the CycloneDX property object used
# to identify components fetched by the given tool name.
hermeto_found_by_property(name) := _hermeto_found_by_property(name)

_hermeto_found_by_property(name) := {
	"name": sprintf("%s:found_by", [name]),
	"value": name,
}

_hermeto_names := ["cachi2", "hermeto"]

rule_data_packages_key := "disallowed_packages"

rule_data_attributes_key := "disallowed_attributes"

rule_data_allowed_external_references_key := "allowed_external_references"

rule_data_disallowed_external_references_key := "disallowed_external_references"

rule_data_allowed_package_sources_key := "allowed_package_sources"
