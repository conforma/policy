#
# METADATA
# title: Tekton Task Step image policies
# description: >-
#   This package ensures that a Task definition contains valid values for the image references
#   used by the Task's steps.
#
package step_images

import rego.v1

import data.lib.metadata

# METADATA
# title: Step images are valid
# description: >-
#   Confirm that each step in the Task uses a container image that is accessible.
# custom:
#   short_name: step_images_accessible
#   failure_msg: Step %d uses inaccessible image ref '%s'
#   solution: >-
#     Make sure the container image used in each step of the Task is pushed to the
#     registry and that it can be fetched.
#   effective_on: 2025-02-10T00:00:00Z
#
deny contains result if {
	input.kind == "Task"

	some step_index, step in input.spec.steps
	image_ref := step.image
	not ec.oci.image_manifest(image_ref)

	result := metadata.result_helper_with_term(
		rego.metadata.chain(),
		[step_index, image_ref],
		image_ref,
	)
}
