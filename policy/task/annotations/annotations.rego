#
# METADATA
# title: Tekton Task annotations
# description: >-
#   Policies to verify that a Tekton Task definition uses well formed expected
#   annotations .
#
package annotations

import rego.v1

import data.lib.metadata
import data.lib.tkn_bundle

# METADATA
# title: Task definition uses expires-on annotation in RFC3339 format
# description: >-
#   Make sure to use the date format in RFC3339 format in the
#   "build.appstudio.redhat.com/expires-on" annotation.
# custom:
#   short_name: expires_on_format
#   failure_msg: >-
#     Expires on time is not in RFC3339 format: %q
#
deny contains result if {
	some task in tkn_bundle.tasks
	expires_on := task.metadata.annotations[_expires_on_annotation]

	not time.parse_rfc3339_ns(expires_on)

	result := metadata.result_helper(rego.metadata.chain(), [expires_on])
}

_expires_on_annotation := "build.appstudio.redhat.com/expires-on"
