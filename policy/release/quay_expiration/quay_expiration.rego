#
# METADATA
# title: Quay expiration
# description: >-
#   Policies to prevent releasing an image to quay that has a quay
#   expiration date. In Konflux images with an expiration date are
#   produced by "on-pr" build pipelines, i.e. pre-merge CI builds,
#   so this is intended to prevent accidentally releasing a CI build.
#
package quay_expiration

import rego.v1

import data.lib

# METADATA
# title: Expires label
# description: >-
#   Check the image metadata for the presence of a "quay.expires-after"
#   label. If it's present then produce a violation. This check is enforced
#   only for a "release", "production", or "staging" pipeline, as determined by
#   the value of the `pipeline_intention` rule data.
# custom:
#   short_name: expires_label
#   pipeline_intention:
#   - release
#   - production
#   - staging
#   failure_msg: The image has a 'quay.expires-after' label set to '%s'
#   solution: >-
#     Make sure the image is built without setting the "quay.expires-after" label. This
#     label is usually set if the container image was built by an "on-pr" pipeline
#     during pre-merge CI.
#   collections:
#   - redhat
#
deny contains result if {
	lib.release_restrictions_apply(rego.metadata.chain())

	# This is where we can access the image labels
	some label_name, label_value in input.image.config.Labels

	# The quay.expires-after label is present
	label_name == "quay.expires-after"

	# This is an edge case that may never happen, but let's assume that if
	# the value is an empty string then it is not an expiration and therefore
	# can be permitted
	count(label_value) > 0

	# Send up the violation the details
	result := lib.result_helper(rego.metadata.chain(), [label_value])
}
