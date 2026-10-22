#
# METADATA
# title: Tekton task build type label checks
# description: >-
#   Policies to verify that a Tekton build task definition has the
#   required build type label.
#
package build_labels

import rego.v1

import data.lib.metadata

import data.lib.tekton

build_label := "build.appstudio.redhat.com/build_type"

# METADATA
# title: Build task has build type label
# description: >-
#   Confirm the build task definition has the required build type label. A defined
#   but malformed `metadata.labels` (for example a list, string, number or null)
#   is treated as not having the label, so that a malformed value cannot silently
#   bypass this check.
# custom:
#   short_name: build_type_label_set
#   failure_msg: The required build label '%s' is missing
#   collections:
#   - redhat_security
#
deny contains result if {
	# Only applies when labels are provided at all; a complete absence of labels
	# is reported by build_task_has_label instead.
	labels := tekton.task_labels(input)
	not _has_build_label(labels)
	result := metadata.result_helper(rego.metadata.chain(), [build_label])
}

# METADATA
# title: Build task has label
# description: >-
#   Confirm that the build task definition includes at least one label.
# custom:
#   short_name: build_task_has_label
#   failure_msg: The task definition does not include any labels
#   collections:
#   - redhat_security
#
deny contains result if {
	not tekton.task_labels(input)
	result := metadata.result_helper(rego.metadata.chain(), [])
}

# _has_build_label is true only when labels is a proper object that contains the
# required build-type label. A non-object value is never considered to have it.
_has_build_label(labels) if {
	is_object(labels)
	build_label in object.keys(labels)
}
