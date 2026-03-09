#
# METADATA
# title: RPM Repos
# description: >-
#   This package defines rules to confirm that all RPM packages listed
#   in SBOMs specify a known and permitted repository id.
#
package rpm_repos

import rego.v1

import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data
import data.lib.sbom
import data.lib.sets

# METADATA
# title: Known repo id list provided
# description: >-
#   A list of known and permitted repository ids should be available in the rule data.
# custom:
#   short_name: rule_data_provided
#   failure_msg: "Rule data '%s' has unexpected format: %s"
#   solution: >-
#     Include a data source that provides a list of known repository ids under the
#     'known_rpm_repositories' key under the top level 'rule_data' key. This list can
#     extended with the 'extra_rpm_repositories' rule data key. The contents of both
#     lists are combined.
#   collections:
#   - redhat
#   - redhat_rpms
#   - policy_data
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [_rule_data_key, e.message], e.severity)
}

# METADATA
# title: All rpms have known repo ids
# description: >-
#   Each RPM package listed in an SBOM must specify the repository id that it comes from,
#   and that repository id must be present in the list of known and permitted repository ids.
#   Currently this is rule enforced only for SBOM components created by cachi2.
# custom:
#   short_name: ids_known
#   failure_msg: 'RPM repo id check failed: %s'
#   solution: >-
#     Ensure every rpm comes from a known and permitted repository, and that the data in the
#     SBOM correctly records that.
#   collections:
#   - redhat
#   - redhat_rpms
#   effective_on: "2024-11-10T00:00:00Z"
#
deny contains result if {
	# Don't bother with this unless we have valid rule data
	count(_rule_data_errors) == 0

	some bad_purl, msg in _repo_id_errors
	result := metadata.result_helper_with_term(rego.metadata.chain(), [msg], bad_purl)
}

_rule_data_errors contains error if {
	some error in j.validate_schema(
		_known_repo_ids,
		{
			"$schema": "http://json-schema.org/draft-07/schema#",
			"type": "array",
			"items": {"type": "string"},
			# The list of repo IDs is a combination of two different lists which are often managed
			# by different people. It's ok if those overlap.
			"uniqueItems": false,
			"minItems": 1,
		},
	)
}

_repo_id_errors[bad_purl] := msg if {
	bad_purls := all_c2_rpm_purls - _plain_purls(all_c2_purls_with_repo_ids)
	count(bad_purls) > 0

	truncated := _truncate(bad_purls)
	some bad_purl in truncated.values
	msg := sprintf("An RPM component in the SBOM did not specify a repository_id value in its purl: %s%s", [
		bad_purl,
		_truncated_msg(truncated.remainder),
	])
}

_repo_id_errors[bad_purl] := msg if {
	bad_purls := all_c2_purls_with_repo_ids - all_c2_purls_with_known_repo_ids
	count(bad_purls) > 0

	truncated := _truncate(_plain_purls(bad_purls))
	some bad_purl in truncated.values
	msg := sprintf("An RPM component in the SBOM specified an unknown or disallowed repository_id: %s%s", [
		bad_purl,
		_truncated_msg(truncated.remainder),
	])
}

all_c2_purls_with_known_repo_ids contains purl_obj if {
	some purl_obj in all_c2_purls_with_repo_ids
	purl_obj.repo_id in _known_repo_ids
}

all_c2_purls_with_repo_ids contains purl_obj if {
	some purl in all_c2_rpm_purls
	ec.purl.is_valid(purl)

	purl_obj := {
		"purl": purl,
		"repo_id": _purl_qualifier("repository_id", purl),
	}
}

# Pick out only the rpm components discovered by cachi2, since they're the
# only components that have repo ids currently. This means rpm components
# discovered by syft are excluded from this check.
#
# (The reason we can have both of them together in the same sbom is because
# different sboms are merged together to produce the final sbom.)
#
all_c2_rpm_purls contains purl if {
	some entity in sbom.all_rpm_entities
	entity.found_by_cachi2
	purl := entity.purl
}

_known_repo_ids := combined if {
	extra := rule_data.get(_rule_data_extras_key)
	known := rule_data.get(_rule_data_key)
	combined := array.concat(extra, known)
} else := known if {
	known := rule_data.get(_rule_data_key)
}

_rule_data_key := "known_rpm_repositories"

_rule_data_extras_key := "extra_rpm_repositories"

# Converts a list of purl objects, as returned by
# all_purls_with_repo_ids, back into a list of purl strings
_plain_purls(purl_objs) := {purl_obj.purl | some purl_obj in purl_objs}

# Extract a named qualifier from a purl
_purl_qualifier(key, purl) := result if {
	parsed_purl := ec.purl.parse(purl)
	some qualifier in parsed_purl.qualifiers
	qualifier.key == key
	result := qualifier.value
}

# SBOMs often list many hundreds of components. Let's avoid producing that
# many violations if none of the purls are passing this test. (In future we
# might move this to a shared library or to ec.)

# If there are more than this then truncate the list
_truncate_threshold := 10

# ...but not if the N in the "N more" is less than this
_min_remainder_count := 4

_truncate(collection) := {"values": truncated, "remainder": remainder_count} if {
	remainder_count := count(collection) - _truncate_threshold
	remainder_count >= _min_remainder_count
	truncated := array.slice(sets.to_array(collection), 0, _truncate_threshold)
} else := {"values": collection, "remainder": 0}

_truncated_msg(remainder) := msg if {
	remainder > 0
	msg := sprintf(" (%d additional similar violations not separately listed)", [remainder])
} else := ""
