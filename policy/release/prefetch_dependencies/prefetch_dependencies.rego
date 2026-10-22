#
# METADATA
# title: Prefetch Dependencies Task
# description: >-
#   This package verifies that the prefetch-dependencies task is invoked with
#   appropriate parameters to ensure secure dependency fetching.
#
package prefetch_dependencies

import rego.v1

import data.lib
import data.lib.metadata
import data.lib.tekton

# METADATA
# title: Prefetch dependencies mode parameter check
# description: >-
#   Verify the prefetch-dependencies task in the PipelineRun attestation was not
#   invoked with the "permissive" mode parameter, which could compromise security.
#   A present but wrong-typed `mode` value (for example a list or a number) is
#   treated as insecure as well, so that a malformed value cannot silently bypass
#   this check.
# custom:
#   short_name: mode_not_permissive
#   failure_msg: >-
#     Task '%s' was invoked with an insecure or malformed mode parameter
#   solution: >-
#     Change the mode parameter of the prefetch-dependencies task from 'permissive'
#     to a more secure value, and make sure it is provided as a string. The
#     permissive mode may allow insecure dependency fetching practices.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.tasks(attestation)
	some name in {"prefetch-dependencies", "prefetch-dependencies-oci-ta"}
	name in tekton.task_names(task)
	_insecure_mode(task)
	result := metadata.result_helper(rego.metadata.chain(), [name])
}

# METADATA
# title: Prefetch task has package registry proxy enabled
# description: >-
#   Verify that prefetch-dependencies tasks have the
#   enable-package-registry-proxy parameter set to true. This ensures
#   that dependency prefetching uses the package registry proxy.
# custom:
#   short_name: package_registry_proxy_enabled
#   failure_msg: >-
#     Task '%s' does not have the enable-package-registry-proxy parameter set to true
#   solution: >-
#     Make sure the prefetch-dependencies task has the input parameter
#     'enable-package-registry-proxy' set to 'true'.
#   collections:
#   - redhat
#   - redhat_security
#   depends_on:
#   - attestation_type.known_attestation_type
#   effective_on: 2026-05-13T00:00:00Z
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.tasks(attestation)
	some name in {"prefetch-dependencies", "prefetch-dependencies-oci-ta"}
	name in tekton.task_names(task)
	not _task_has_proxy_enabled(task)
	result := metadata.result_helper(rego.metadata.chain(), [name])
}

_task_has_proxy_enabled(task) if {
	tekton.task_param(task, "enable-package-registry-proxy") == "true"
}

# The "permissive" mode is explicitly insecure.
_insecure_mode(task) if {
	tekton.task_param(task, "mode") == "permissive"
}

# A present but non-string mode is malformed and must not be trusted. An absent
# mode leaves task_param undefined, so this remains a no-op in that case.
_insecure_mode(task) if {
	mode := tekton.task_param(task, "mode")
	not is_string(mode)
}
