package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_image_result if {
	results := [
		{
			"name": "IMAGE_URL",
			"value": "image1",
		},
		{
			"name": "IMAGE_DIGEST",
			"value": "1234",
		},
		{
			"name": "OTHER_IMAGE_URL",
			"value": "image2\n",
		},
		{
			"name": "OTHER_IMAGE_DIGEST",
			"value": "4321\n",
		},
	]
	lib.assert_equal(["image1", "image2"], tekton.task_result_artifact_url(resolved_slsav1_task("task1", [], results)))
	lib.assert_equal(["1234", "4321"], tekton.task_result_artifact_digest(resolved_slsav1_task("task1", [], results)))
}

test_artifact_result if {
	results := [
		{
			"name": "ARTIFACT_URI",
			"value": "image1",
		},
		{
			"name": "ARTIFACT_DIGEST",
			"value": "1234",
		},
		{
			"name": "OTEHR_ARTIFACT_URI",
			"value": "image2\n",
		},
		{
			"name": "OTHER_ARTIFACT_DIGEST",
			"value": "4321\n",
		},
	]
	lib.assert_equal(["image1", "image2"], tekton.task_result_artifact_url(resolved_slsav1_task("task1", [], results)))
	lib.assert_equal(["1234", "4321"], tekton.task_result_artifact_digest(resolved_slsav1_task("task1", [], results)))
}

test_images_result if {
	results := [{
		"name": "IMAGES",
		"value": "img1@sha256:digest1, img2@sha256:digest2\n",
	}]
	lib.assert_equal(["img1", "img2"], tekton.task_result_artifact_url(resolved_slsav1_task("task1", [], results)))
	lib.assert_equal(
		["sha256:digest1", "sha256:digest2"],
		tekton.task_result_artifact_digest(resolved_slsav1_task("task1", [], results)),
	)
}

test_artifact_outputs_result if {
	results := [
		{
			"name": "ARTIFACT_OUTPUTS",
			"value": {"uri": "img1", "digest": "1234"},
		},
		{
			"name": "OTHER_ARTIFACT_OUTPUTS",
			"value": {"uri": "img2\n", "digest": "4321\n"},
		},
	]
	lib.assert_equal(["img1", "img2"], tekton.task_result_artifact_url(resolved_slsav1_task("task1", [], results)))
	lib.assert_equal(["1234", "4321"], tekton.task_result_artifact_digest(resolved_slsav1_task("task1", [], results)))
}

test_invalid_result_name if {
	results := [{
		"name": "INVALID_OUTPUTS",
		"value": {"uri": "img1", "digest": "1234"},
	}]
	lib.assert_empty(tekton.task_result_artifact_url(resolved_slsav1_task("task1", [], results)))
	lib.assert_empty(tekton.task_result_artifact_digest(resolved_slsav1_task("task1", [], results)))
}

test_images_with_digests if {
	results_artifact_outputs := [{
		"name": "ARTIFACT_OUTPUTS",
		"value": {"uri": "img1\n", "digest": "1234\n"},
	}]
	results_images := [
		{
			"name": "image1_IMAGE_URL",
			"value": "img1\n",
		},
		{
			"name": "image1_IMAGE_DIGEST",
			"value": "1234\n",
		},
	]
	results_images_unordered := [
		{
			"name": "image1_IMAGE_URL",
			"value": "img1\n",
		},
		{
			"name": "image2_IMAGE_DIGEST",
			"value": "5678\n",
		},
		{
			"name": "image2_IMAGE_URL",
			"value": "img2\n",
		},
		{
			"name": "image1_IMAGE_DIGEST",
			"value": "1234\n",
		},
	]
	tasks_artifacts := [
		resolved_slsav1_task("task1", [], results_artifact_outputs),
		resolved_slsav1_task("task2", [], results_artifact_outputs),
	]
	lib.assert_equal(["img1@1234", "img1@1234"], tekton.images_with_digests(tasks_artifacts))

	tasks_images := [resolved_slsav1_task("task1", [], results_images), resolved_slsav1_task("task2", [], results_images)]
	lib.assert_equal(["img1@1234", "img1@1234"], tekton.images_with_digests(tasks_images))

	tasks_ordered := [resolved_slsav1_task("task1", [], results_images_unordered)]
	lib.assert_equal(["img1@1234", "img2@5678"], tekton.images_with_digests(tasks_ordered))
}

test_mixed_results if {
	results := [
		{
			"name": "image1_IMAGE_URL",
			"value": "image-url-img1",
		},
		{
			"name": "image1_IMAGE_DIGEST",
			"value": "2345",
		},
		{
			"name": "image2_IMAGE_URL",
			"value": "image-url-img2",
		},
		{
			"name": "image2_IMAGE_DIGEST",
			"value": "3456",
		},
		{
			"name": "IMAGES",
			"value": "images-1@sha256:4567,images-2@sha256:5678",
		},
		{
			"name": "image1_ARTIFACT_URI",
			"value": "image-artifact-1",
		},
		{
			"name": "image1_ARTIFACT_DIGEST",
			"value": "sha256:6789",
		},
		{
			"name": "image2_ARTIFACT_URI",
			"value": "image-artifact-1",
		},
		{
			"name": "image2_ARTIFACT_DIGEST",
			"value": "sha256:7890",
		},
		{
			"name": "image1_ARTIFACT_OUTPUTS",
			"value": {"uri": "artifact-outputs-img1", "digest": "sha256:1234"},
		},
		{
			"name": "image2_ARTIFACT_OUTPUTS",
			"value": {"uri": "artifact-outputs-img2", "digest": "sha256:9801"},
		},
	]

	expected := [
		"image-url-img1@2345",
		"image-url-img2@3456",
		"image-artifact-1@sha256:6789",
		"image-artifact-1@sha256:7890",
		"images-1@sha256:4567",
		"images-2@sha256:5678",
		"artifact-outputs-img1@sha256:1234",
		"artifact-outputs-img2@sha256:9801",
	]

	lib.assert_equal(expected, tekton.images_with_digests([resolved_slsav1_task("task1", [], results)]))
}

test_no_results if {
	lib.assert_empty(tekton.images_with_digests([resolved_slsav1_task("task1", [], [])]))
}
