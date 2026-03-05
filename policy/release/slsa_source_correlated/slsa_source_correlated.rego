#
# METADATA
# title: SLSA - Verification model - Source
# description: >-
#   SLSA v1 verification model states:
#
#   "...artifacts are verified to ensure they meet the producer defined
#   expectations of where the package source code was retrieved from..."
#
#   This package correlates the provided source code reference with the source
#   code referenced in the attestation.
#
package slsa_source_correlated

import rego.v1

import data.lib.utils
import data.lib
import data.lib.json as j

# METADATA
# title: Source code reference provided
# description: >-
#   Check if the expected source code reference is provided.
# custom:
#   short_name: source_code_reference_provided
#   failure_msg: Expected source code reference was not provided for verification
#   solution: >-
#     Provide the expected source code reference in inputs.
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   - redhat_rpms
deny contains result if {
	source := object.get(input, ["image", "source"], {})
	count(source) == 0

	result := utils.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Source reference
# description: >-
#   Attestation contains source reference.
# custom:
#   short_name: attested_source_code_reference
#   failure_msg: The attested material contains no source code reference
#   solution: >-
#     Check that the attestation creation process includes the source code reference
#     in the predicate.materials for SLSA Provenance v0.2, or in
#     predicate.buildDefinition.resolvedDependencies for SLSA Provenance v1.0
#     attestations. Check that the Version Control System prefix is the list of the
#     supported VCS types in rule data (`supported_vcs` key).
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	count(_source_references) == 0

	result := utils.result_helper(rego.metadata.chain(), [])
}

# METADATA
# title: Expected source code reference
# description: >-
#   Verify that the provided source code reference is the one being attested.
# custom:
#   short_name: expected_source_code_reference
#   failure_msg: The expected source code reference %q is not attested
#   solution: >-
#     The source code reference in the attestation doesn't match the expected and
#     provided source code reference. Make sure that the provided source code
#     reference is correct, and if it is make sure that the build process is
#     configured to retrieve the source code from the appropriate source code
#     repository. Make sure that the source code reference is pointing to a
#     explicit revision not to a symbolic identifier, e.g. a branch or tag name.
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
deny contains result if {
	count(_source_references) > 0

	some expected_source in _expected_sources

	# TODO: this is rather loose, this checks that the expected source is
	# one of the attested sources, thus allowing also the inclusion of
	# unexpected source
	count(expected_source.refs & _source_references) == 0

	some attested_source in _source_references

	result := utils.result_helper_with_term(
		rego.metadata.chain(),
		[sprintf("%s@%s", [expected_source.expected_vcs_uri, expected_source.expected_revision])], attested_source,
	)
}

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `supported_vcs` and `supported_digests`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   collections:
#   - minimal
#   - slsa3
#   - redhat
#   - redhat_rpms
#   - policy_data
deny contains result if {
	some e in _rule_data_errors
	result := utils.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_refs(expected_vcs_uri, expected_revision) := refs if {
	uris := {
		# URI as is
		expected_vcs_uri,
		# Tolerate duplicated .git suffix due to attestor bugs
		trim_suffix(expected_vcs_uri, ".git"),
		# Tolerate missing .git suffix
		sprintf("%s.git", [expected_vcs_uri]),
		# Tolerate trailing slash
		trim_suffix(expected_vcs_uri, "/"),
		# Tolerate trailing slash with missing .git suffix
		sprintf("%s.git", [trim_suffix(expected_vcs_uri, "/")]),
	}

	refs := {ref |
		some uri in uris
		some algo in {"sha1", "gitCommit"}
		ref := sprintf("%s@%s:%s", [uri, algo, expected_revision])
	}
}

_expected_sources contains expected_source if {
	some vcs_type, vcs_info in input.image.source

	# e.g. git+https://github.com/...
	expected_vcs_uri := sprintf("%s+%s", [vcs_type, object.get(vcs_info, ["url"], "")])
	expected_revision := object.get(vcs_info, ["revision"], "")
	expected_source := {
		"expected_vcs_uri": expected_vcs_uri,
		"expected_revision": expected_revision,
		"refs": _refs(expected_vcs_uri, expected_revision),
	}
}

# SLSA Provenance
_source_references contains ref if {
	some att in lib.slsa_provenance_attestations
	some material in lib.attestation_materials(att)
	some digest_alg in object.keys(material.digest)
	some supported_vcs_type in utils.rule_data("supported_vcs")

	# the material.uri is a kind of vcs_type, lets us ignore other, non-vcs, materials
	startswith(material.uri, sprintf("%s+", [supported_vcs_type]))

	# make sure the digest algorithm is supported
	digest_alg in utils.rule_data("supported_digests")

	# note, the digest_alg is not compared, it is expected that the value
	# matches the expected reference
	ref := sprintf("%s@%s:%s", [material.uri, digest_alg, material.digest[digest_alg]])
}

_rule_data_errors contains error if {
	some key in ["supported_vcs", "supported_digests"]

	some e in j.validate_schema(
		utils.rule_data(key),
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			"uniqueItems": true,
		},
	)
	error := {
		"message": sprintf("Rule data %s has unexpected format: %s", [key, e.message]),
		"severity": e.severity,
	}
}
