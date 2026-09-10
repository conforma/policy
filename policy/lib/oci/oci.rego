package lib.oci

import data.lib.image
import data.lib.sigstore
import rego.v1

parsed_blob(ref) := ec.oci.parsed_blob(ref)

# parsed_blob_if_valid is a tolerant variant that returns undefined
# instead of erroring when the blob is missing or not valid JSON.
parsed_blob_if_valid(ref) := result if {
	raw := ec.oci.blob(ref)
	json.is_valid(raw)
	result := json.unmarshal(raw)
}

parsed_blob_from_image(ref) := result if {
	parsed := image.parse(ref)
	manifest := ec.oci.image_manifest(ref)
	layer := manifest.layers[0]
	blob_ref := image.str({"repo": parsed.repo, "digest": layer.digest})
	result := parsed_blob(blob_ref)
}

# verified_image_referrers returns the subset of OCI referrers whose
# signatures verify against the provided signing identity. Returns an empty
# set when the identity is not a usable verification config (fail-closed).
verified_image_referrers(ref, identity) := {result.item |
	some result in _image_referrer_results(ref, identity)
	result.errors == []
}

# image_referrer_failures returns referrers whose signature verification
# failed, along with the error details. Each element is
# {"item": <referrer>, "errors": [<string>, ...]}.
image_referrer_failures(ref, identity) := {result |
	some result in _image_referrer_results(ref, identity)
	count(result.errors) > 0
}

_image_referrer_results(ref, identity) := {result |
	_usable_identity(identity)
	some referrer in ec.oci.image_referrers(ref)
	info := ec.sigstore.verify_image(referrer.ref, identity)
	result := {"item": referrer, "errors": object.get(info, "errors", [])}
}

# verified_image_tag_refs returns the subset of image tag refs whose
# signatures verify against the provided signing identity. Returns an empty
# set when the identity is not a usable verification config (fail-closed).
verified_image_tag_refs(ref, identity) := {result.item |
	some result in _image_tag_ref_results(ref, identity)
	result.errors == []
}

# image_tag_ref_failures returns tag refs whose signature verification
# failed, along with the error details. Each element is
# {"item": <tag-ref-string>, "errors": [<string>, ...]}.
image_tag_ref_failures(ref, identity) := {result |
	some result in _image_tag_ref_results(ref, identity)
	count(result.errors) > 0
}

_image_tag_ref_results(ref, identity) := {result |
	_usable_identity(identity)
	some tag_ref in ec.oci.image_tag_refs(ref)
	info := ec.sigstore.verify_image(tag_ref, identity)
	result := {"item": tag_ref, "errors": object.get(info, "errors", [])}
}

# _usable_identity is true only for a signing identity that is a valid,
# complete sigstore verification config. Invalid or absent identities cause
# referrer/tag SBOMs to be excluded (fail-closed); the invalid config itself
# is reported separately via sigstore.validate in the consuming package.
_usable_identity(identity) if {
	is_object(identity)
	sigstore.validate(identity) == []
}

# blob_from_image fetches the blob content of the first layer from an OCI
# image manifest identified by ref. This is useful when ref is a tag-based
# reference where ec.oci.blob cannot be used directly because it requires
# digest-based references.
blob_from_image(ref) := blob if {
	parsed := image.parse(ref)
	manifest := ec.oci.image_manifest(ref)
	layer := manifest.layers[0]
	blob_ref := image.str({"repo": parsed.repo, "digest": layer.digest})
	blob := ec.oci.blob(blob_ref)
}
