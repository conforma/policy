#
# METADATA
# title: Source image
# description: >-
#   This package is reponsible for verifying the source container image associated with the image
#   being validated.
#
package source_image

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.tekton

# METADATA
# title: Exists
# description: Verify the source container image exists.
# custom:
#   short_name: exists
#   failure_msg: "%s"
#   collections:
#   - redhat
#   effective_on: 2024-06-05T00:00:00Z
#
deny contains result if {
	some error in _source_image_errors
	result := metadata.result_helper(rego.metadata.chain(), [error])
}

# METADATA
# title: Signed
# description: Verify the source container image is signed.
# custom:
#   short_name: signed
#   failure_msg: "%s"
#   depends_on:
#   - source_image.exists
#   collections:
#   - redhat
#   effective_on: 2024-05-04T00:00:00Z
#
deny contains result if {
	some error in _source_image_sig_errors
	result := metadata.result_helper(rego.metadata.chain(), [error])
}

_source_image_errors contains error if {
	count(_source_images) == 0
	error := "No source image references found"
}

_source_image_errors contains error if {
	some img in _source_images
	not ec.oci.image_manifest(img)
	error := sprintf("Unable to access source image %q", [img])
}

_source_image_errors contains error if {
	some img in _source_images
	manifest := ec.oci.image_manifest(img)
	layers := object.get(manifest, "layers", [])
	count(layers) == 0
	error := sprintf("Source image has no layers %q", [img])
}

_source_image_sig_errors contains error if {
	some img in _source_images
	info := ec.sigstore.verify_image(img, lib.sigstore_opts)
	some raw_error in info.errors
	error := sprintf("Image signature verification failed for %s: %s", [img, raw_error])
}

# _source_images is a set of image references. Each corresponding to the
# SOURCE_IMAGE_URL@SOURCE_IMAGE_DIGEST parameter of a source-build Task.
_source_images contains img if {
	some att in lib.pipelinerun_attestations
	some task in tekton.source_build_tasks(att)

	url := trim_space(tekton.task_result(task, "SOURCE_IMAGE_URL"))
	digest := trim_space(tekton.task_result(task, "SOURCE_IMAGE_DIGEST"))
	img := sprintf("%s@%s", [url, digest])
}
