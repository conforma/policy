package lib.tekton

import rego.v1

import data.lib.image

# Return an object that represents the task "name", "kind", and "bundle". "bundle" is
# omitted if a bundle is not used.
#
# As task reference can take different shapes depending on which resolver is being used.
# When a bundle reference is used, there are two mechanisms. The old-style which uses
# the .bundle attribute, and the new-style via the Bundle Resolver. It is technically
# possible to create a task reference that contains both styles. In such cases, Tekton
# gives precedence to the old-style. Further, Tekton falls back to the local resolver if
# a bundle is not used in neither format. The "else" usage in this function ensures the
# same precendence order is honored.
# regal ignore:rule-length
task_ref(task) := j if {
	# Handle old-style bundle reference
	r := _ref(task)
	bundle := r.bundle
	pinned_ref := _pinned_ref_for_bundle(bundle)
	i := _with_pinned_ref(
		{
			"bundle": bundle,
			"name": _ref_name(task),
			"kind": lower(object.get(r, "kind", "task")),
			"key": _key_for_bundle(bundle),
		},
		pinned_ref,
	)
	tagged_ref := _tagged_ref_for_bundle(bundle)
	j = _with_tagged_ref(i, tagged_ref)
} else := j if {
	# Handle bundle-resolver reference
	r := _ref(task)
	r.resolver == "bundles"
	bundle := _param(r, "bundle", "")
	pinned_ref := _pinned_ref_for_bundle(bundle)
	i := _with_pinned_ref(
		{
			"bundle": bundle,
			"name": _ref_name(task),
			"kind": lower(_param(r, "kind", "task")),
			"key": _key_for_bundle(bundle),
		},
		pinned_ref,
	)
	tagged_ref := _tagged_ref_for_bundle(bundle)
	j = _with_tagged_ref(i, tagged_ref)
} else := i if {
	r := _ref(task)
	r.resolver == "git"
	revision := _param(r, "revision", "")
	url := _param(r, "url", "")
	canonical_url := _with_git_suffix(_with_git_prefix(url))
	path_in_repo := _param(r, "pathInRepo", "")
	pinned_ref := _pinned_ref_for_git(revision)
	i := _with_pinned_ref(
		{
			"url": url,
			"revision": revision,
			"pathInRepo": path_in_repo,
			"name": _ref_name(task),
			"kind": lower(object.get(r, "kind", "task")),
			"key": _key_for_git(canonical_url, path_in_repo),
		},
		pinned_ref,
	)
} else := i if {
	# Handle inlined Task definitions
	_ref(task) == {}
	i := _with_pinned_ref(
		{
			# The Task definition itself is inlined without a name. Use a special value here to
			# distinguish from other reference types.
			"name": _no_task_name,
			"kind": "task",
			"key": _unkonwn_task_key,
		},
		_inlined_pinned_ref,
	)
} else := i if {
	# Handle local reference
	r := _ref(task)
	i := _with_pinned_ref(
		{
			"name": _ref_name(task),
			"kind": lower(object.get(r, "kind", "task")),
			"key": _unkonwn_task_key,
		},
		"",
	)
}

default _is_sha1(_) := false

_is_sha1(value) if regex.match(`^[0-9a-f]{40}$`, value)

_param(task_ref, name, fallback) := value if {
	some param in task_ref.params
	param.name == name
	value := param.value
} else := fallback

_ref(task) := r if {
	# Reference from within a PipelineRun slsa v0.2 attestation
	r := task.ref
} else := r if {
	# Reference from within a Pipeline definition or a PipelineRun slsa v1.0 attestation
	r := task.taskRef
} else := r if {
	# reference from a taskRun in a slsav1 attestation
	r := task.spec.taskRef
} else := {}

# _ref_name returns the name of the given Task. This is the name taken from the Task definition. It
# tries to grab the name from the "tekton.dev/task" which is automatically added by the Tekton
# Pipeline controller: https://tekton.dev/docs/pipelines/labels/#automatic-labeling
# There are a few reasons the label may not be available. The first is due to incomplete data,
# usually in the unit tests. The second is if this is processing a Pipeline/Task definition
# directly. Finally, the last is if the Task is an inlined/embedded Task.
_ref_name(task) := value if {
	# Location of labels in SLSA Provenance v1.0
	some label, value in task.metadata.labels
	label == "tekton.dev/task"
} else := value if {
	# Location of labels in SLSA Provenance v0.2
	some label, value in task.invocation.environment.labels
	label == "tekton.dev/task"
} else := name if {
	# Some resolvers specify the name of the Task as a parameter, e.g. bundles and hub.
	name := _param(_ref(task), "name", "")
	name != ""
} else := name if {
	# Pipeline/Task definition
	name := _ref(task).name
} else := _no_task_name

_key_for_bundle(bundle) := key if {
	parts := image.parse(bundle)
	parts.tag != ""
	key := sprintf("oci://%s:%s", [parts.repo, parts.tag])
} else := key if {
	parts := image.parse(bundle)
	key := sprintf("oci://%s", [parts.repo])
} else := sprintf("oci://%s", [bundle])

_key_for_git(url, path_in_repo) := sprintf("%s//%s", [url, path_in_repo])

_with_git_prefix(url) := with_prefix if {
	not startswith(url, "git+")
	with_prefix := sprintf("git+%s", [url])
} else := url

_with_git_suffix(url) := with_suffix if {
	not endswith(url, ".git")
	with_suffix := sprintf("%s.git", [url])
} else := url

_tagged_ref_for_bundle(bundle) := tag if {
	parts := image.parse(bundle)
	tag := parts.tag
} else := ""

_pinned_ref_for_bundle(bundle) := digest if {
	parts := image.parse(bundle)
	digest := parts.digest
} else := ""

_pinned_ref_for_git(revision) := revision if {
	_is_sha1(revision)
} else := ""

_with_tagged_ref(obj, tagged_ref) := new_obj if {
	tagged_ref != ""
	new_obj := object.union(obj, {
		"tagged": true,
		"tagged_ref": tagged_ref,
	})
} else := new_obj if {
	new_obj := object.union(obj, {"tagged": false})
}

_with_pinned_ref(obj, pinned_ref) := new_obj if {
	pinned_ref != ""
	new_obj := object.union(obj, {
		"pinned": true,
		"pinned_ref": pinned_ref,
	})
} else := new_obj if {
	new_obj := object.union(obj, {"pinned": false})
}

_no_task_name := "<NAMELESS>"

_inlined_pinned_ref := "<INLINED>"

_unkonwn_task_key := "<UNKNOWN>"
