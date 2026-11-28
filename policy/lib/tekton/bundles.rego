package lib.tekton

import rego.v1

import data.lib.image

# Return the bundle reference as is
bundle(task) := task_ref(task).bundle

# Returns a subset of tasks that do not use a bundle reference.
disallowed_task_reference(tasks) := {task |
	some task in tasks
	not bundle(task)
}

# Returns a subset of tasks that use an empty bundle reference.
empty_task_bundle_reference(tasks) := {task |
	some task in tasks
	bundle(task) == ""
}

# Returns a subset of tasks that use bundle references not pinned to a digest.
unpinned_task_bundle(tasks) := {task |
	some task in tasks
	bundle_ref := bundle(task)
	image.parse(bundle_ref)
	not image.is_pinned(bundle_ref)
}
