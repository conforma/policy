package lib.tekton

import rego.v1

# handle the output artifacts from Tekton Chains
# https://tekton.dev/docs/chains/slsa-provenance/#output-artifacts

task_result_artifact_url(task) := array.concat(
	_task_result_image_urls(task),
	array.concat(
		_task_result_artifact_uris(task),
		array.concat(
			_task_result_images_urls(task),
			_task_result_artifact_outputs_urls(task),
		),
	),
)

# returns the value of a task result with name IMAGE_URL
_task_result_image_urls(task) := _non_empty_strings(task_result_endswith(task, "IMAGE_URL"))

# returns the value of a task result with name ARTIFACT_URI
_task_result_artifact_uris(task) := _non_empty_strings(task_result_endswith(task, "ARTIFACT_URI"))

# returns the image url from the task result IMAGES
_task_result_images_urls(task) := _non_empty_strings([split_item[0] |
	some result in task_result_endswith(task, "IMAGES")
	some image in split(result, ",")
	split_item := split(image, "@")
])

# returns the image url from the task result ARTIFACT_OUTPUTS
_task_result_artifact_outputs_urls(task) := _non_empty_strings([result.uri |
	some result in task_result_endswith(task, "ARTIFACT_OUTPUTS")
])

task_result_artifact_digest(task) := array.concat(
	_task_result_image_digests(task),
	array.concat(
		_task_result_artifact_digests(task),
		array.concat(
			_task_result_images_digests(task),
			_task_result_artifact_outputs_digests(task),
		),
	),
)

# returns the value of a task result with name IMAGE_DIGEST
_task_result_image_digests(task) := _non_empty_strings(task_result_endswith(task, "IMAGE_DIGEST"))

# returns the value of a task result with name ARTIFACT_DIGEST
_task_result_artifact_digests(task) := _non_empty_strings(task_result_endswith(task, "ARTIFACT_DIGEST"))

# returns the image digest from the task result IMAGES
_task_result_images_digests(task) := _non_empty_strings([split_item[1] |
	some result in task_result_endswith(task, "IMAGES")
	some image in split(result, ",")
	split_item := split(image, "@")
])

# returns the image digest from the task result ARTIFACT_OUTPUTS
_task_result_artifact_outputs_digests(task) := _non_empty_strings([result.digest |
	some result in task_result_endswith(task, "ARTIFACT_OUTPUTS")
])

_non_empty_strings(values) := [trimmed_value |
	some value in values
	trimmed_value := trim_space(value)
	count(trimmed_value) > 0
]

images_with_digests(tasks) := [sprintf("%v@%v", [image, digest]) |
	some task in tasks
	some image_index, image in task_result_artifact_url(task)
	some digest_index, digest in task_result_artifact_digest(task)
	image_index == digest_index
]
