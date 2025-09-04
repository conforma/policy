#
# METADATA
# title: Pre-build-script task checks
# description: >-
#   This package verifies that the pre-build-script tasks in the
#   attestation are executed in a controlled environment
#
package pre_build_script_task

import rego.v1

import data.lib
import data.lib.image
import data.lib.sbom
import data.lib.tekton

# METADATA
# title: Script runner image comes from allowed registry
# description: >-
#   Verify that the images used to run the pre-build script tasks come from a known
#   set of trusted registries to reduce potential supply chain attacks. By default this
#   policy defines trusted registries as registries that are fully maintained by Red
#   Hat and only contain content produced by Red Hat. The list of allowed registries
#   can be customized by setting the `allowed_registry_prefixes` list in the rule data.
# custom:
#   short_name: pre_build_script_task_runner_image_allowed
#   failure_msg: Pre-Build-Script task runner image %q is from a disallowed registry
#   solution: >-
#     Make sure the image referenced in the parameter 'SCRIPT_RUNNER_IMAGE' comes from
#     a trusted registry. The list of trusted registries is a configurable
#     xref:cli:ROOT:configuration.adoc#_data_sources[data source].
#   collections:
#   - redhat
#   depends_on:
#   - attestation_type.known_attestation_type
#   - base_image_registries.allowed_registries_provided
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	image_ref := tekton.task_param(task, _pre_build_script_runner_image_param)
	not _image_ref_permitted(image_ref)
	repo := image.parse(image_ref).repo
	result := lib.result_helper_with_term(rego.metadata.chain(), [image_ref], repo)
}

# METADATA
# title: Script runner image is listed in the task results
# description: >-
#   Verify that the image used to run the pre-build script task is
#   listed in the task result SCRIPT_RUNNER_IMAGE_REFERENCE
# custom:
#   short_name: pre_build_script_task_runner_image_in_results
#   failure_msg: >-
#     The runner image used for the pre-Build-Script task '%s' is not
#     listed in the task results
#   solution: >-
#     Make sure the image used to run the pre-build task is referenced
#     in the 'SCRIPT_RUNNER_IMAGE_REFERENCE' task result.
#   collections:
#   - redhat
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	not tekton.task_result(task, _pre_build_run_script_runner_image_result)
	result := lib.result_helper(rego.metadata.chain(), [tekton.task_name(task)])
}

# METADATA
# title: Script runner image is a valid image reference
# description: >-
#   Verify that a valid image reference is specified as image being
#   used to run the pre-build script task
# custom:
#   short_name: valid_pre_build_script_task_runner_image_ref
#   failure_msg: >-
#     Pre-Build-Script task runner image %q is not a valid
#     image reference
#   solution: >-
#     Make sure the value in the 'SCRIPT_RUNNER_IMAGE_REFERENCE' result
#     is a valid image reference
#   collections:
#   - redhat
#
deny contains result if {
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	ref := tekton.task_result(task, _pre_build_run_script_runner_image_result)
	not image.parse(ref)
	result := lib.result_helper(rego.metadata.chain(), [ref])
}

# METADATA
# title: Script runner image is included in the sbom
# description: >-
#   Verify that the image used to run the pre-build script task is
#   included in the SBOM
# custom:
#   short_name: pre_build_script_task_runner_image_in_sbom
#   failure_msg: Pre-Build-Script task runner image %q is not in the SBOM
#   solution: >-
#     Make sure the image referenced in the 'SCRIPT_RUNNER_IMAGE_REFERENCE'
#     result is included in the SBOM.
#   collections:
#   - redhat
#
deny contains result if {
	# This check does not apply to the image index for multi-arch builds
	# because its sbom is different to the sbom for the per-arch images
	not image.is_image_index(input.image.ref)
	some pre_build_image in _script_runner_image_refs
	image.parse(pre_build_image)
	not _is_image_in_sbom(pre_build_image)
	result := lib.result_helper(rego.metadata.chain(), [pre_build_image])
}

_pre_build_script_runner_image_param := "SCRIPT_RUNNER_IMAGE"

_image_ref_permitted(image_ref) if {
	allowed_prefixes := lib.rule_data(_rule_data_allowed_registries_key)
	some allowed_prefix in allowed_prefixes
	startswith(image_ref, allowed_prefix)
}

_rule_data_allowed_registries_key := "allowed_registry_prefixes"

_script_runner_image_refs := [image_ref |
	some attestation in lib.pipelinerun_attestations
	some task in tekton.pre_build_tasks(attestation)
	image_ref := tekton.task_result(task, _pre_build_run_script_runner_image_result)
]

_pre_build_run_script_runner_image_result := "SCRIPT_RUNNER_IMAGE_REFERENCE"

_is_image_in_sbom(image_ref) if {
	some s in sbom.all_sboms
	some purl in _purls_from_sbom(s)
	image_ref_from_purl := sbom.image_ref_from_purl(purl)
	image.equal_ref(image_ref_from_purl, image_ref)
}

_purls_from_sbom(s) := purls if {
	# CycloneDX
	purls := {component.purl |
		some component in s.components
	}
	count(purls) > 0
} else := purls if {
	# SPDX
	purls := {ref.referenceLocator |
		some pkg in s.packages
		some ref in pkg.externalRefs
		ref.referenceType == "purl"
		ref.referenceCategory in {"PACKAGE_MANAGER", "PACKAGE-MANAGER"}
	}
	count(purls) > 0
}
