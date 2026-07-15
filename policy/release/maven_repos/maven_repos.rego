# METADATA
# title: All maven artifacts have known repository URLs
# description: >-
#   Each Maven package listed in an SBOM must specify the repository URL that it
#   comes from, and that URL must be present in the list of known and permitted
#   Maven repositories. If no URL is specified, the package is assumed to come
#   from Maven Central.
package release.maven_repos

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.rule_data
import data.lib.sbom

# METADATA
# title: Policy data validation
# description: Ensures the required allowed_maven_repositories list is provided.
# custom:
#   short_name: policy_data_missing
#   failure_msg: Policy data is missing the required "%s" list
#   solution: >-
#     Ensure that 'allowed_maven_repositories' is defined in the rule_data
#     provided to the policy, and that it contains a list of authorized
#     repository URLs.
#   collections:
#     - redhat_maven
#     - redhat_security
#     - policy_data
deny contains result if {
	some key in _rule_data_errors
	result := lib.result_helper(rego.metadata.chain(), [key])
}

# METADATA
# title: Known Repository URLs
# description: >-
#   Each Maven package listed in an SBOM must specify the repository URL that it
#   comes from, and that URL must be present in the list of known and permitted
#   Maven repositories. If no URL is specified, the package is assumed to come
#   from Maven Central.
# custom:
#    short_name: deny_unpermitted_urls
#    failure_msg: '%s'
#    solution: >-
#      The Maven artifact originates from an untrusted or unpermitted repository.
#      To resolve this, ensure the dependency is sourced from a repository defined
#      in the 'allowed_maven_repositories' list in your policy configuration.
#      If the repository is internal, add its URL to the allowed list in rule_data.
#    effective_on: 2026-05-10T00:00:00Z
#    collections:
#      - redhat_maven
#      - redhat_security
deny contains result if {
	some err in _repo_url_errors
	result := metadata.result_helper_with_term(rego.metadata.chain(), [err.msg], err.purl)
}

_repo_url_errors contains err if {
	some pkg in sbom.maven_packages
	source := _get_effective_url(pkg.repository_url)
	not _url_is_permitted(source)
	err := {
		"purl": pkg.purl,
		"msg": sprintf("Package %q (source: %q) is not in the permitted list", [pkg.purl, source]),
	}
}

_get_effective_url(url) := url if {
	url != ""
} else := "https://repo.maven.apache.org/maven2/"

_url_is_permitted(url) if {
	permitted := rule_data.get("allowed_maven_repositories")
	url in permitted
}

_rule_data_errors contains key if {
	key := "allowed_maven_repositories"
	data_list := rule_data.get(key)
	_is_invalid_data(data_list)
}

_is_invalid_data(val) if not is_array(val)

_is_invalid_data(val) if {
	is_array(val)
	count(val) == 0
}
