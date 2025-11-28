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
	lib.assert_equal(
		[t |
			some task in tekton.tasks({"statement": input})
			t := tekton.task_data(task)
		],
		[
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-apply-tags:0.2@sha256:f44be1bf0262471f2f503f5e19da5f0628dcaf968c86272a2ad6b4871e708448",
				"name": "apply-tags",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-buildah-oci-ta:0.5@sha256:38d08ea58511a67f8754dc025feebdec8ae342fb4e25bc67a3726ec84f7cb7d1",
				"name": "buildah-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-build-image-index:0.1@sha256:79784d53749584bc5a8de32142ec4e2f01cdbf42c20d94e59280e0b927c8597d",
				"name": "build-image-index",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-source-build-oci-ta:0.3@sha256:36d44f2924f60da00a079a9ab7ce25ad8b2ad593c16d90509203c125ff0ccd46",
				"name": "source-build-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-clair-scan:0.3@sha256:a7cc183967f89c4ac100d04ab8f81e54733beee60a0528208107c9a22d3c43af",
				"name": "clair-scan",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-clamav-scan:0.3@sha256:b0bd59748cda4a7abf311e4f448e6c1d00c6b6d8c0ecc1c2eb33e08dc0e0b802",
				"name": "clamav-scan",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-git-clone-oci-ta:0.1@sha256:f21c34e50500edc84e4889d85fd71a80d79182b16c044adc7f5ecda021c6dfc7",
				"name": "git-clone-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-coverity-availability-check:0.2@sha256:db2b267dc15e4ed17f704ee91b8e9b38068e1a35b1018a328fdca621819d74c6",
				"name": "coverity-availability-check",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-deprecated-image-check:0.5@sha256:1d07d16810c26713f3d875083924d93697900147364360587ccb5a63f2c31012",
				"name": "deprecated-image-check",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-ecosystem-cert-preflight-checks:0.2@sha256:7db70c6cf23f39b9aad8b75285df31ed2c1213d87842cd4502ffc268808c96c6",
				"name": "ecosystem-cert-preflight-checks",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-init:0.2@sha256:bbf313b09740fb39b3343bc69ee94b2a2c21d16a9304f9b7c111c305558fc346",
				"name": "init",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-prefetch-dependencies-oci-ta:0.2@sha256:dc82a7270aace9b1c26f7e96f8ccab2752e53d32980c41a45e1733baad76cde6",
				"name": "prefetch-dependencies-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-push-dockerfile-oci-ta:0.1@sha256:2bc5b3afc5de56da0f06eac60b65e86f6b861b16a63f48579fc0bac7d657e14c",
				"name": "push-dockerfile-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/konflux-vanguard/task-rpms-signature-scan:0.2@sha256:06977232e67509e5540528ff6c3b081b23fc5bf3e40fb3e2d09a086d5c3243fc",
				"name": "rpms-signature-scan",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-sast-coverity-check-oci-ta:0.3@sha256:cdbe1a968676e4f5519b082bf1e27a4cdcf66dd60af66dbc26b3e604f957f7e9",
				"name": "sast-coverity-check-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-sast-shell-check-oci-ta:0.1@sha256:bf7bdde00b7212f730c1356672290af6f38d070da2c8a316987b5c32fd49e0b9",
				"name": "sast-shell-check-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-sast-snyk-check-oci-ta:0.4@sha256:181d63c126e3119a9d57b8feed4eb66a875b5208c3e90724c22758e65dca8733",
				"name": "sast-snyk-check-oci-ta",
			},
			{
				# regal ignore:line-length
				"bundle": "quay.io/konflux-ci/tekton-catalog/task-sast-unicode-check-oci-ta:0.3@sha256:a2bde66f6b4164620298c7d709b8f08515409404000fa1dc2260d2508b135651",
				"name": "sast-unicode-check-oci-ta",
			},
		],
	) with input as att_05_slsa_v1_0_tekton_build_type_pipeline_in_cluster
}
