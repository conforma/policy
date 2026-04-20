#
# METADATA
# title: Tekton task bundle checks
# description: >-
#   Policies to detect Tekton task bundles, extract task definitions
#   from bundle layers, and delegate validation to existing task policies.
#
package task_bundle

import rego.v1

import data.annotations
import data.kind
import data.results
import data.step_image_registries
import data.step_images

# ===== Detection =====

# Check if the current image is a Tekton task bundle by looking for
# dev.tekton.image.* annotations on its OCI manifest layers.
_is_task_bundle if {
	_manifest != null
	some layer in _manifest.layers
	_is_tekton_layer(layer)
}

_manifest := ec.oci.image_manifest(input.image.ref)

_is_tekton_layer(layer) if {
	layer.annotations["dev.tekton.image.kind"]
	layer.annotations["dev.tekton.image.name"]
	layer.annotations["dev.tekton.image.apiVersion"]
}

# ===== Extraction =====

# Extract all task definitions from the bundle. Each layer with
# kind "task" contains a tar archive with a single entry named
# after the task (no file extension) holding the task definition as JSON.
_task_definitions := [task |
	_is_task_bundle
	some layer in _manifest.layers
	layer.annotations["dev.tekton.image.kind"] == "task"
	task_name := layer.annotations["dev.tekton.image.name"]

	blob_ref := sprintf("%s@%s", [_repo, layer.digest])

	task := _extract_task(blob_ref, task_name)
	task != null
]

_repo := repo if {
	parts := split(input.image.ref, "@")
	repo := parts[0]
}

_extract_task(blob_ref, task_name) := task if {
	files := ec.oci.blob_files(blob_ref, [task_name])
	task := files[task_name]
}

_task_name(task) := task.metadata.name if {
	task.metadata.name
}

_task_name(task) := "<unnamed>" if {
	not task.metadata.name
}

# ===== Delegation to existing task policies =====

deny contains _delegate(task, r) if {
	some task in _task_definitions
	some r in kind.deny with input as task
}

deny contains _delegate(task, r) if {
	some task in _task_definitions
	some r in annotations.deny with input as task
}

deny contains _delegate(task, r) if {
	some task in _task_definitions
	some r in step_images.deny with input as task
}

deny contains _delegate(task, r) if {
	some task in _task_definitions
	some r in step_image_registries.deny with input as task
}

deny contains _delegate(task, r) if {
	some task in _task_definitions
	some r in results.deny with input as task
}

_delegate(task, r) := object.union(r, {
	"code": sprintf("task_bundle.%s", [r.code]),
	"msg": sprintf("[%s] %s", [_task_name(task), r.msg]),
})

# ===== Informational rules =====

# METADATA
# title: Task bundle detected
# description: >-
#   Reports that a Tekton task bundle was detected and how many
#   tasks were extracted from it.
# custom:
#   short_name: detected
#   failure_msg: "Detected task bundle with %d task(s) extracted"
#
warn contains result if {
	_is_task_bundle
	count(_task_definitions) > 0
	result := {
		"code": "task_bundle.detected",
		"msg": sprintf("Detected task bundle with %d task(s) extracted", [count(_task_definitions)]),
	}
}

# METADATA
# title: No tasks extracted
# description: >-
#   A task bundle was detected but no tasks could be extracted from it.
# custom:
#   short_name: no_tasks
#   failure_msg: "Task bundle detected but no tasks could be extracted from %s"
#
deny contains result if {
	_is_task_bundle
	count(_task_definitions) == 0
	result := {
		"code": "task_bundle.no_tasks",
		"msg": sprintf("Task bundle detected but no tasks could be extracted from %s", [input.image.ref]),
	}
}
