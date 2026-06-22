package lib.oci

import data.lib.image
import rego.v1

# parsed_blob fetches and parses a JSON blob. Once the CLI ships the
# ec.oci.parsed_blob builtin (EC-1836), swap this to use it for
# cross-eval caching.
parsed_blob(ref) := json.unmarshal(ec.oci.blob(ref))

parsed_blob_from_image(ref) := result if {
	parsed := image.parse(ref)
	manifest := ec.oci.image_manifest(ref)
	layer := manifest.layers[0]
	blob_ref := image.str({"repo": parsed.repo, "digest": layer.digest})
	result := parsed_blob(blob_ref)
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
