package lib.konflux

import rego.v1

import data.lib
import data.lib.image
import data.lib.tekton

# Currently, it's not possible to determine if the image being validated is an Image Index or an
# Image Manifest, see https://github.com/conforma/cli/issues/2121. This function is
# implemented as a workaround. It uses Konflux-specific heuristics to determine if the provided
# image is an Image Index.
is_validating_image_index if {
	image_index_digests := {digest |
		some attestation in lib.pipelinerun_attestations
		some task in tekton.build_tasks(attestation)

		# In Konflux, the Task that creates an Image Index emits the IMAGES result which contains
		# all of the related Image Manifests.
		count(trim_space(tekton.task_result(task, "IMAGES"))) > 0
		digest := trim_space(tekton.task_result(task, "IMAGE_DIGEST"))
		count(digest) > 0
	}

	image.parse(input.image.ref).digest in image_index_digests
}
