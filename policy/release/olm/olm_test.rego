package olm_test

import rego.v1

import data.lib
import data.lib.tekton_test
import data.lib_test
import data.olm

unpinned := "registry.io/repo/msd:no_digest"

unpinned_related_img := "registry.io/repo/msd:latest"

pinned0 := "registry.io/repository/image@sha256:dosa"

pinned1 := "registry.io/repository/image@sha256:cafe"

pinned2 := "registry.io/repository/image2@sha256:tea"

pinned3 := "registry.io/repository/image3@sha256:coffee"

pinned_ref := {"digest": "sha256:cafe", "repo": "registry.io/repository/image", "tag": ""}

pinned_ref2 := {"digest": "sha256:tea", "repo": "registry.io/repository/image2", "tag": ""}

component0 := {
	"name": "Unnamed",
	"containerImage": pinned0,
	"source": {},
}

component1 := {
	"name": "Unnamed",
	"containerImage": pinned1,
	"source": {},
}

component2 := {
	"name": "pinned_image2",
	"containerImage": pinned2,
	"source": {},
}

component3 := {
	"name": "pinned_image3",
	"containerImage": pinned3,
	"source": {},
}

unpinned_component := {
	"name": "unpinned_image",
	"containerImage": unpinned,
	"source": {},
}

manifest := {
	"apiVersion": "operators.coreos.com/v1alpha1",
	"kind": "ClusterServiceVersion",
	"metadata": {"annotations": {
		"containerImage": pinned1,
		"enclosurePicture": sprintf("%s,  %s", [pinned1, pinned2]),
		"features.operators.openshift.io/disconnected": "true",
		"features.operators.openshift.io/fips-compliant": "true",
		"features.operators.openshift.io/proxy-aware": "true",
		"features.operators.openshift.io/tls-profiles": "false",
		"features.operators.openshift.io/token-auth-aws": "false",
		"features.operators.openshift.io/token-auth-azure": "false",
		"features.operators.openshift.io/token-auth-gcp": "false",
		"operators.openshift.io/valid-subscription": `["spam"]`,
		"alm-examples": `"endpoint": "http://example:4317" spam`,
		# regal ignore:line-length
		"features.operators.image": `{"kind":"Namespace","apiVersion":"v1","metadata":{"name":"openshift-workload-availability","annotations":{"openshift.io/node-selector":""}}}`,
	}},
	"spec": {
		"version": "0.1.3",
		"relatedImages": [{"image": pinned1}],
		"install": {"spec": {"deployments": [{
			"metadata": {"annotations": {"docket": sprintf("%s\n  %s", [pinned1, pinned2])}},
			"spec": {"template": {
				"metadata": {"name": "c1"},
				"spec": {
					"containers": [{
						"name": "c1",
						"image": pinned1,
						"env": [{"name": "RELATED_IMAGE_C1", "value": pinned1}],
					}],
					"initContainers": [{
						"name": "i1",
						"image": pinned1,
						"env": [{"name": "RELATED_IMAGE_E1", "value": pinned1}],
					}],
				},
			}},
		}]}},
	},
	"not-metadata": {"annotations": {"something": pinned2}},
	"metadata-without-annotations": {"metadata": {}},
	"metadata-with-empty-annotations": {"metadata": {"annotations": {}}},
}

# regal ignore:rule-length
test_all_image_ref if {
	lib.assert_equal(
		[
			{"path": "spec.relatedImages[0].image", "ref": pinned_ref},
			{"path": "annotations.containerImage", "ref": pinned_ref},
			{"path": "annotations[\"containerImage\"]", "ref": pinned_ref},
			{"path": "annotations[\"enclosurePicture\"]", "ref": pinned_ref},
			{"path": "annotations[\"enclosurePicture\"]", "ref": pinned_ref2},
			{"path": "annotations[\"docket\"]", "ref": pinned_ref},
			{"path": "annotations[\"docket\"]", "ref": pinned_ref2},
			{
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].image`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.initContainers[0 ("i1")].image`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].env["RELATED_IMAGE_C1"]`,
				"ref": pinned_ref,
			},
			{
				# regal ignore:line-length
				"path": `spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.initContainers[0 ("i1")].env["RELATED_IMAGE_E1"]`,
				"ref": pinned_ref,
			},
		],
		olm.all_image_ref(manifest),
	)
}

test_all_good if {
	lib.assert_empty(olm.deny) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_all_good_custom_dir if {
	lib.assert_empty(olm.deny) with input.image.files as {"other/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "other/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_related_img_unpinned if {
	unpinned_manifest = json.patch(manifest, [{
		"op": "replace",
		"path": "/spec/install/spec/deployments/0/spec/template/spec/containers/0/env/0/value",
		"value": "registry.io/repository:tag",
	}])

	expected = {{
		"code": "olm.unpinned_references",
		# regal ignore:line-length
		"msg": `The "registry.io/repository:tag" image reference is not pinned at spec.install.spec.deployments[0 ("unnamed")].spec.template.spec.containers[0 ("c1")].env["RELATED_IMAGE_C1"].`,
		"term": "registry.io/repository:tag",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": unpinned_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_feature_annotations_format if {
	bad_manifest := json.patch(manifest, [
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1disconnected", "value": false},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1fips-compliant", "value": true},
		{"op": "add", "path": "/metadata/annotations/features.operators.openshift.io~1proxy-aware", "value": 1},
		{"op": "remove", "path": "/metadata/annotations/features.operators.openshift.io~1tls-profiles"},
	])

	expected := {
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/disconnected\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/disconnected",
		},
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/fips-compliant\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/fips-compliant",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"features.operators.openshift.io/proxy-aware\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/proxy-aware",
		},
		{
			"code": "olm.feature_annotations_format",
			# regal ignore:line-length
			"msg": "The annotation \"features.operators.openshift.io/tls-profiles\" is either missing or has an unexpected value",
			"term": "features.operators.openshift.io/tls-profiles",
		},
	}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": bad_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_feature_annotations_format_custom_rule_data if {
	bad_manifest := json.patch(manifest, [
		{"op": "add", "path": "/metadata/annotations/foo", "value": "bar"},
		{"op": "add", "path": "/metadata/annotations/spam", "value": "true"},
	])

	expected := {{
		"code": "olm.feature_annotations_format",
		"msg": "The annotation \"foo\" is either missing or has an unexpected value", "term": "foo",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": bad_manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.required_olm_features_annotations as ["foo", "spam"]
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_required_olm_features_annotations_provided if {
	expected_empty := {{
		"code": "olm.required_olm_features_annotations_provided",
		# regal ignore:line-length
		"msg": "Rule data required_olm_features_annotations has unexpected format: (Root): Array must have at least 1 items",
		"severity": "failure",
	}}
	lib.assert_equal_results(olm.deny, expected_empty) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.required_olm_features_annotations as []

	d := [
		# Wrong type
		1,
		# Duplicated items
		"foo",
		"foo",
	]

	expected := {
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation \"foo\" is either missing or has an unexpected value",
			"term": "foo",
		},
		{
			"code": "olm.feature_annotations_format",
			"msg": "The annotation '\\x01' is either missing or has an unexpected value",
			"term": 1,
		},
		{
			"code": "olm.required_olm_features_annotations_provided",
			"msg": "Rule data required_olm_features_annotations has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "olm.required_olm_features_annotations_provided",
			# regal ignore:line-length
			"msg": "Rule data required_olm_features_annotations has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with data.rule_data.required_olm_features_annotations as d
}

test_csv_semver_format_bad_semver if {
	csv := json.patch(manifest, [{"op": "add", "path": "/spec/version", "value": "spam"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"spam\", is not a valid semver",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_csv_semver_format_missing if {
	csv := json.patch(manifest, [{"op": "remove", "path": "/spec/version"}])

	expected := {{
		"code": "olm.csv_semver_format",
		"msg": "The ClusterServiceVersion spec.version, \"<MISSING>\", is not a valid semver",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as {"manifests/csv.yaml": csv}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_subscriptions_annotation_format if {
	path := "/metadata/annotations/operators.openshift.io~1valid-subscription"
	files := {
		"m/csv-no-annotations.yaml": json.patch(manifest, [{"op": "remove", "path": "/metadata/annotations"}]),
		"m/csv-invalid-json.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "invalid-json"}]),
		"m/csv-empty.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "[]"}]),
		"m/csv-dupes.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": `["spam", "spam"]`}]),
		"m/csv-bad-type.yaml": json.patch(manifest, [{"op": "add", "path": path, "value": "[1]"}]),
	}

	expected := {
		{
			"code": "olm.subscriptions_annotation_format",
			"msg": "Value of operators.openshift.io/valid-subscription annotation is missing",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			"msg": "Value of operators.openshift.io/valid-subscription annotation is not valid JSON",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: (Root): Array must have at least 1 items",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: (Root): array items[0,1] must be unique",
			"severity": "failure",
		},
		{
			"code": "olm.subscriptions_annotation_format",
			# regal ignore:line-length
			"msg": "Value of operators.openshift.io/valid-subscription annotation is invalid: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(olm.deny, expected) with input.image.files as files
		with input.image.config.Labels as {olm.manifestv1: "m/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_unpinned_snapshot_references_operator if {
	expected := {{
		"code": "olm.unpinned_snapshot_references",
		"msg": "The \"registry.io/repo/msd:no_digest\" image reference is not pinned in the input snapshot.",
		"term": "registry.io/repo/msd:no_digest",
	}}
	lib.assert_equal_results(olm.deny, expected) with input.snapshot.components as [unpinned_component, component1]
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as unpinned_component.containerImage
}

test_unpinned_snapshot_references_different_input if {
	lib.assert_empty(olm.deny) with input.snapshot.components as [unpinned_component]
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
		with ec.oci.image_manifest as `{"config": {"digest": "sha256:goat"}}`
		with input.image.ref as pinned2
}

test_unmapped_references_in_operator if {
	expected := {{
		"code": "olm.unmapped_references",
		"msg": "The \"registry.io/repository/image2@sha256:tea\" CSV image reference is not in the snapshot or accessible.",
		"term": "registry.io/repository/image2@sha256:tea",
	}}

	lib.assert_equal_results(olm.deny, expected) with input.snapshot.components as [component1]
		with input.image.files as {"manifests/csv.yaml": manifest}
		with data.rule_data as {"allowed_olm_image_registry_prefixes": ["registry.io"]}
		with ec.oci.image_manifest as _mock_image_partial
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
}

test_unpinned_related_images if {
	expected_deny := {{
		"code": "olm.unpinned_related_images",
		"msg": "2 related images are not pinned with a digest: registry.io/repo/msd:latest, registry.io/repo/msd:latest.",
	}}

	lib.assert_equal_results(olm.deny, expected_deny) with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"] # regal ignore:line-length
		with input.snapshot.components as [component0]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_unpinned_image_partial
		with ec.oci.blob as _mock_unpinned_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

test_inaccessible_related_images if {
	expected_deny := {{
		"code": "olm.inaccessible_related_images",
		"msg": "The \"registry.io/repository/image2@sha256:tea\" related image reference is not accessible.",
		"term": "registry.io/repository/image2@sha256:tea",
	}}

	lib.assert_equal_results(olm.deny, expected_deny) with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"] # regal ignore:line-length
		with input.snapshot.components as [component1]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_partial
		with ec.oci.blob as _mock_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

mock_ec_oci_image_descriptor("registry.io/repository/image@sha256:cafe") := `{"config": {"digest": "sha256:cafe"}}`

mock_ec_oci_image_descriptor("registry.io/repository/image3@sha256:coffee") := `{"config": {"digest": "sha256:coffee"}}`

mock_ec_oci_image_descriptor("registry.io/repository/image2@sha256:tea") := false

mock_ec_oci_image_descriptor("registry.io/repo/msd:latest") := `{"config": {"digest": ""}}`

test_mock_cafe_descriptor if {
	# Test case that uses the mock_ec_oci_image_descriptor for cafe image
	expected := `{"config": {"digest": "sha256:cafe"}}`
	lib.assert_equal(mock_ec_oci_image_descriptor("registry.io/repository/image@sha256:cafe"), expected)
}

test_unmapped_references_none_found if {
	lib.assert_empty(olm.deny) with input.snapshot.components as [component1, component2]
		with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io"]
}

test_allowed_registries if {
	# This should pass since registry.io is a member of allowed_olm_image_registry_prefixes
	lib.assert_empty(olm.deny) with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io", "registry.redhat.io"] # regal ignore:line-length
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
}

test_bundle_image_index if {
	descriptor := {"mediaType": "application/vnd.oci.image.index.v1+json"}

	expected_deny := {{
		"code": "olm.olm_bundle_multi_arch",
		"msg": "The \"registry.io/repository/image@sha256:cafe\" bundle image is a multi-arch reference.",
		"term": "registry.io/repository/image@sha256:cafe",
	}}

	lib.assert_equal_results(olm.deny, expected_deny) with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.io", "registry.redhat.io"] # regal ignore:line-length
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
		with input.image.ref as pinned1
		with ec.oci.descriptor as descriptor
}

test_unallowed_registries if {
	expected := {
		{
			"code": "olm.allowed_registries",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image@sha256:cafe\" CSV image reference is not from an allowed registry.",
			"term": "registry.io/repository/image",
		},
		{
			"code": "olm.allowed_registries",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image2@sha256:tea\" CSV image reference is not from an allowed registry.",
			"term": "registry.io/repository/image2",
		},
	}

	# This expects failure as registry.io is not a member of allowed_olm_image_registry_prefixes
	lib.assert_equal_results(olm.deny, expected) with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.access.redhat.com", "registry.redhat.io"] # regal ignore:line-length
		with input.image.config.Labels as {olm.manifestv1: "manifests/"}
		with input.image.files as {"manifests/csv.yaml": manifest}
}

test_allowed_registries_related if {
	expected_deny := {
		{
			"code": "olm.allowed_registries_related",
			"msg": "The \"registry.io/repository/image@sha256:cafe\" related image reference is not from an allowed registry.",
			"term": "registry.io/repository/image",
		},
		{
			"code": "olm.allowed_registries_related",
			"msg": "The \"registry.io/repository/image2@sha256:tea\" related image reference is not from an allowed registry.",
			"term": "registry.io/repository/image2",
		},
		{
			"code": "olm.allowed_registries_related",
			# regal ignore:line-length
			"msg": "The \"registry.io/repository/image3@sha256:coffee\" related image reference is not from an allowed registry.",
			"term": "registry.io/repository/image3",
		},
	}

	lib.assert_equal_results(olm.deny, expected_deny) with data.rule_data.allowed_olm_image_registry_prefixes as ["registry.access.redhat.com", "registry.redhat.io"] # regal ignore:line-length
		with input.snapshot.components as [component1, component2, component3]
		with input.attestations as _with_related_images
		with input.image.ref as "registry.io/repository/image@sha256:image_digest"
		with ec.oci.image_manifest as _mock_image_all
		with ec.oci.blob as _mock_blob
		with ec.oci.descriptor as mock_ec_oci_image_descriptor
}

_related_images := [pinned1, pinned2, pinned3]

_unpinned_related_images := [unpinned_related_img]

_manifests_all := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm._related_images_oci_mime_type,
		"digest": "sha256:related_blob_digest",
	}]},
	"registry.io/repository/image@sha256:cafe": {"config": {"digest": "sha256:cafe"}},
	"registry.io/repository/image2@sha256:tea": {"config": {"digest": "sha256:tea"}},
	"registry.io/repository/image3@sha256:coffee": {"config": {"digest": "sha256:coffee"}},
}

_manifests_partial := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm._related_images_oci_mime_type,
		"digest": "sha256:related_blob_digest",
	}]},
	"registry.io/repository/image@sha256:cafe": {"config": {"digest": "sha256:cafe"}},
}

_manifests_unpinned := {
	"registry.io/repository/image@sha256:related_digest": {"layers": [{
		"mediaType": olm._related_images_oci_mime_type,
		"digest": "sha256:related_unpinned_blob_digest",
	}]},
	"registry.io/repository/image@sha256:dosa": {"config": {"digest": "sha256:dosa"}},
}

_blobs := {"registry.io/repository/image@sha256:related_blob_digest": json.marshal(_related_images)}

unpinned_blob_key := "registry.io/repository/image@sha256:related_unpinned_blob_digest"

_unpinned_blobs := {unpinned_blob_key: json.marshal(_unpinned_related_images)}

_mock_image_all(ref) := _manifests_all[ref]

_mock_image_partial(ref) := _manifests_partial[ref]

_mock_unpinned_image_partial(ref) := _manifests_unpinned[ref]

_mock_blob(ref) := _blobs[ref]

_mock_unpinned_blob(ref) := _unpinned_blobs[ref]

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_with_related_images := _attestations_with_attachment("sha256:related_digest")

_attestations_with_attachment(attachment) := attestations if {
	slsav1_task_with_result := tekton_test.slsav1_task_result_ref(
		"validate-fbc",
		[{
			"name": olm._related_images_result_name,
			"type": "string",
			"value": attachment,
		}],
	)

	attestations := [
		lib_test.att_mock_helper_ref(
			olm._related_images_result_name,
			attachment,
			"validate-fbc",
			_bundle,
		),
		lib_test.mock_slsav1_attestation_with_tasks([tekton_test.slsav1_task_bundle(slsav1_task_with_result, _bundle)]),
	]
}

test_image_ref_with_digest if {
	img := {"repo": "registry.io/repo", "digest": "sha256:abc", "tag": "latest"}
	expected := "registry.io/repo@sha256:abc"
	lib.assert_equal(olm._image_ref(img), expected)
}

test_image_ref_with_tag if {
	img := {"repo": "registry.io/repo", "digest": "", "tag": "latest"}
	expected := "registry.io/repo:latest"
	lib.assert_equal(olm._image_ref(img), expected)
}

test_image_ref_with_repo_only if {
	img := {"repo": "registry.io/repo", "digest": "", "tag": ""}
	expected := "registry.io/repo"
	lib.assert_equal(olm._image_ref(img), expected)
}
