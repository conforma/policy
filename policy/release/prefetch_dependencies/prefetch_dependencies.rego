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
# custom:
#   short_name: mode_not_permissive
#   failure_msg: >-
#     Task 'prefetch-dependencies' was invoked with mode parameter set to 'permissive'
#   solution: >-
#     Change the mode parameter of the prefetch-dependencies task from 'permissive'
#     to a more secure value. The permissive mode may allow insecure dependency
#     fetching practices.
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.tasks(attestation)
	some name in {"prefetch-dependencies", "prefetch-dependencies-oci-ta"}
	name in tekton.task_names(task)
	tekton.task_param(task, "mode") == "permissive"
	result := metadata.result_helper(rego.metadata.chain(), [])
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
#   depends_on:
#   - attestation_type.known_attestation_type
#   effective_on: 2026-06-01T00:00:00Z
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
