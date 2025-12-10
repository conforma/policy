package lib.tekton_test

import rego.v1

import data.lib
import data.lib.tekton

test_slsa_v02_task_extraction if {
	lib.assert_equal(
		[t |
			some task in tekton.tasks({"statement": input})
			t := tekton.task_data(task)
		],
		[
			{"name": "mock-av-scanner"},
			{"name": "<NAMELESS>"},
			{
				# regal ignore:line-length
				"bundle": "quay.io/lucarval/test-policies-chains@sha256:ae5952d5aac1664fbeae9191d9445244051792af903d28d3e0084e9d9b7cce61",
				"name": "mock-build",
			},
			{"name": "mock-git-clone"},
		],
	) with input as att_01_slsa_v0_2_pipeline_in_cluster
}

test_slsa_v1_task_extraction if {
	tasks_data := [t |
		some task in tekton.tasks({"statement": att_05_slsa_v1_0_tekton_build_type_pipeline_in_cluster})
		t := tekton.task_data(task)
	]

	expected := [
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah-oci-ta:0.7@sha256:916781b75e5f42a2e0b578b3ab3418e8bcc305168b2cd26ff41c8057e5c9ec28",
			"name": "buildah-oci-ta",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-ecosystem-cert-preflight-checks:0.2@sha256:04f75593558f79a27da2336400bc63d460bf0c5669e3c13f40ee2fb650b1ad1e",
			"name": "ecosystem-cert-preflight-checks",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-git-clone-oci-ta:0.1@sha256:ea64f5b99202621e78ed3d74b00df5750cbf572c391e6da1956396f5945e4e11",
			"name": "git-clone-oci-ta",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-prefetch-dependencies-oci-ta:0.2@sha256:3fa0204a481044b21f0e784ce39cbd25e8fb49c664a5458f3eef351fff1c906e",
			"name": "prefetch-dependencies-oci-ta",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-init:0.2@sha256:4072de81ade0a75ad1eaa5449a7ff02bba84757064549a81b48c28fab3aeca59",
			"name": "init",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-coverity-availability-check:0.2@sha256:5623e48314ffd583e9cab383011dc0763b6c92b09c4f427b8bfcca885394a21c",
			"name": "coverity-availability-check",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-deprecated-image-check:0.5@sha256:f59175d9a0a60411738228dfe568af4684af4aa5e7e05c832927cb917801d489",
			"name": "deprecated-image-check",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-build-image-index:0.2@sha256:803ae1ecf35bc5d22be9882819e942e4b699cb17655055afc6bb6b02d34cfab8",
			"name": "build-image-index",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-push-dockerfile-oci-ta:0.1@sha256:08bba4a659ecd48f871bef00b80af58954e5a09fcbb28a1783ddd640c4f6535e",
			"name": "push-dockerfile-oci-ta",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/konflux-vanguard/task-rpms-signature-scan:0.2@sha256:13cf619a8c24e5a565f1b3f20f6998273d3108a2866e04076b6f0dd967251af3",
			"name": "rpms-signature-scan",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-sast-snyk-check-oci-ta:0.4@sha256:60f2dac41844d222086ff7f477e51f3563716b183d87db89f603d6f604c21760",
			"name": "sast-snyk-check-oci-ta",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-sast-shell-check-oci-ta:0.1@sha256:1f0fcba24ebc447d9f8a2ea2e8f262fa435d6c523ca6b0346cd67261551fc9ed",
			"name": "sast-shell-check-oci-ta",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-clamav-scan:0.3@sha256:f3d2d179cddcc07d0228d9f52959a233037a3afa2619d0a8b2effbb467db80c3",
			"name": "clamav-scan",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-clair-scan:0.3@sha256:ee558db6af779ab162163ec88f288a5c1b2d5f70c3361f3690a474866e3bdc74",
			"name": "clair-scan",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-sast-unicode-check-oci-ta:0.3@sha256:1833c618170ab9deb8455667f220df8e88d16ccd630a2361366f594e2bdcb712",
			"name": "sast-unicode-check-oci-ta",
		},
		{
			# regal ignore:line-length
			"bundle": "quay.io/konflux-ci/tekton-catalog/task-apply-tags:0.2@sha256:a61d8a6d0ba804869e8fe57a9289161817afad379ef2d7433d75ae40a148e2ec",
			"name": "apply-tags",
		},
	]

	lib.assert_equal(tasks_data, expected)
}
