#
# METADATA
# title: GitHub Certificate Checks
# description: >-
#   Verify attributes on the certificate involved in the image signature when using
#   slsa-github-generator on GitHub Actions with Sigstore Fulcio
#
package github_certificate

import rego.v1

import data.lib.json as j
import data.lib.metadata
import data.lib.rule_data

# METADATA
# title: GitHub Workflow Certificate Extensions
# description: >-
#   Check if the image signature certificate contains the expected GitHub
#   extensions. These are the extensions that represent the GitHub workflow
#   trigger, sha, name, repository, and ref.
# custom:
#   short_name: gh_workflow_extensions
#   failure_msg: 'Missing extension %q'
#   collections:
#   - github
#
warn contains result if {
	some extension in [_TRIGGER, _SHA, _NAME, _REPOSITORY, _REF]
	not _fulcio_extension_value(extension)
	result := metadata.result_helper(rego.metadata.chain(), [extension.name])
}

# METADATA
# title: GitHub Workflow Repository
# description: >-
#   Check if the value of the GitHub Workflow Repository extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_repos` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_repository
#   failure_msg: 'Repository %q not in allowed list: %v'
#   collections:
#   - github
#
deny contains _check_extension(rego.metadata.chain(), "allowed_gh_workflow_repos", _REPOSITORY)

# METADATA
# title: GitHub Workflow Repository
# description: >-
#   Check if the value of the GitHub Workflow Ref extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_refs` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_ref
#   failure_msg: 'Ref %q not in allowed list: %v'
#   collections:
#   - github
#
deny contains _check_extension(rego.metadata.chain(), "allowed_gh_workflow_refs", _REF)

# METADATA
# title: GitHub Workflow Name
# description: >-
#   Check if the value of the GitHub Workflow Name extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_names` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_name
#   failure_msg: 'Name %q not in allowed list: %v'
#   collections:
#   - github
#
deny contains _check_extension(rego.metadata.chain(), "allowed_gh_workflow_names", _NAME)

# METADATA
# title: GitHub Workflow Trigger
# description: >-
#   Check if the value of the GitHub Workflow Trigger extension in the image
#   signature certificate matches one of the allowed values. Use the rule data
#   key `allowed_gh_workflow_triggers` to specify the list of allowed values.
#   An empty allow list, which is the default value, causes this check to succeeded.
# custom:
#   short_name: gh_workflow_trigger
#   failure_msg: 'Trigger %q not in allowed list: %v'
#   collections:
#   - github
#
deny contains _check_extension(rego.metadata.chain(), "allowed_gh_workflow_triggers", _TRIGGER)

# METADATA
# title: Rule data provided
# description: >-
#   Confirm the expected rule data keys have been provided in the expected format. The keys are
#   `allowed_gh_workflow_repos`, `allowed_gh_workflow_refs`, `allowed_gh_workflow_names`,
#   and `allowed_gh_workflow_triggers`.
# custom:
#   short_name: rule_data_provided
#   failure_msg: '%s'
#   solution: If provided, ensure the rule data is in the expected format.
#   collections:
#   - github
#   - policy_data
#
deny contains result if {
	some e in _rule_data_errors
	result := metadata.result_helper_with_severity(rego.metadata.chain(), [e.message], e.severity)
}

_check_extension(chain, key, extension) := result if {
	value := _fulcio_extension_value(extension)
	allowed := rule_data.get(key)
	count(allowed) > 0
	not value in allowed
	result := metadata.result_helper(chain, [value, allowed])
}

_certs contains cert if {
	some sig in input.image.signatures
	cert := crypto.x509.parse_certificates(sig.certificate)[0]
	cert.KeyUsage == 1
	cert.ExtKeyUsage == [3]
}

_fulcio_extension_value(ext) := value if {
	id := [1, 3, 6, 1, 4, 1, 57264, 1, ext.id]
	some cert in _certs
	some extension in cert.Extensions
	extension.Id == id
	value := base64.decode(extension.Value)
}

# regal ignore:prefer-snake-case
_TRIGGER := {"id": 2, "name": "GitHub Workflow Trigger"}

# regal ignore:prefer-snake-case
_SHA := {"id": 3, "name": "GitHub Workflow SHA"}

# regal ignore:prefer-snake-case
_NAME := {"id": 4, "name": "GitHub Workflow Name"}

# regal ignore:prefer-snake-case
_REPOSITORY := {"id": 5, "name": "GitHub Workflow Repository"}

# regal ignore:prefer-snake-case
_REF := {"id": 6, "name": "GitHub Workflow Ref"}

_rule_data_errors contains error if {
	keys := [
		"allowed_gh_workflow_repos",
		"allowed_gh_workflow_refs",
		"allowed_gh_workflow_names",
		"allowed_gh_workflow_triggers",
	]
	some key in keys

	some e in j.validate_schema(
		rule_data.get(key),
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
