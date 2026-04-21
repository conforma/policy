package lib.tkn_bundle

import rego.v1

# tasks returns task definitions from either:
#   - Direct task YAML input (ec validate input)
#   - Task bundle OCI image layers (ec validate image)
tasks contains input if {
	not input.image.ref
}

tasks contains task if {
	manifest := ec.oci.image_manifest(input.image.ref)
	manifest != null
	some layer in manifest.layers
	layer.annotations["dev.tekton.image.kind"] == "task"
	task_name := layer.annotations["dev.tekton.image.name"]

	parts := split(input.image.ref, "@")
	repo := parts[0]
	blob_ref := sprintf("%s@%s", [repo, layer.digest])

	files := ec.oci.blob_files(blob_ref, [task_name])
	task := files[task_name]
}
