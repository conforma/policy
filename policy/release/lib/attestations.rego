package lib

import rego.v1

import data.lib.intoto
import data.lib.rule_data
import data.lib.tekton

slsa_provenance_predicate_type_v1 := "https://slsa.dev/provenance/v1"

slsa_provenance_predicate_type_v02 := "https://slsa.dev/provenance/v0.2"

tekton_pipeline_run := "tekton.dev/v1/PipelineRun"

tekton_slsav1_pipeline_run := "https://tekton.dev/chains/v2/slsa-tekton"

# All allowed provenance buildTypes, sourced from rule_data. The defaults include
# all known Tekton buildTypes for both SLSA v0.2 and v1.
_allowed_provenance_build_types := {t |
	some t in rule_data.get("allowed_provenance_build_types")
}

tekton_task_run := "tekton.dev/v1/TaskRun"

taskrun_att_build_types := {
	tekton_task_run,
	# Legacy build types
	"tekton.dev/v1beta1/TaskRun",
	"https://tekton.dev/attestations/chains@v2",
}

# (We can't call this test_task_result_name since anything prefixed
# with test_ is treated as though it was a test.)
task_test_result_name := "TEST_OUTPUT"

slsa_provenance_attestations := [att |
	some att in input.attestations
	att.statement.predicateType in {slsa_provenance_predicate_type_v1, slsa_provenance_predicate_type_v02}
]

# These are the ones we're interested in
pipelinerun_attestations := array.concat(latest_v02_pipelinerun_attestation, latest_v1_pipelinerun_attestation)

# Helper function to extract buildFinishedOn timestamp from an attestation
# Handles both SLSA v0.2 and v1.0 formats
_build_finished_on(att) := timestamp if {
	# Try SLSA v0.2 path first
	timestamp := att.statement.predicate.metadata.buildFinishedOn
} else := timestamp if {
	# Fallback to SLSA v1.0 path (Tekton Chains non-standard field)
	timestamp := att.statement.predicate.runDetails.metadata.buildFinishedOn
} else := timestamp if {
	# Fallback to SLSA v1.0 spec-compliant path
	timestamp := att.statement.predicate.runDetails.metadata.finishedOn
}

# Returns the latest PipelineRun attestation per type (SLSA v0.2 and v1.0)
# based on the buildFinishedOn timestamp. If there's only one attestation of a type,
# return it regardless of timestamp. Returns a list (empty if none exist).
latest_v02_pipelinerun_attestation := [pipelinerun_slsa_provenance02[0]] if {
	# If there's only one v0.2 attestation, return it regardless of timestamp
	count(pipelinerun_slsa_provenance02) == 1
} else := [att |
	# Multiple v0.2 attestations - filter by timestamp and return latest
	v02_with_timestamp := [a |
		some a in pipelinerun_slsa_provenance02
		_build_finished_on(a)
	]

	# make sure all v0.2 attestations have a timestamp
	count(v02_with_timestamp) == count(pipelinerun_slsa_provenance02)

	# Find the latest v0.2 attestation
	max_v02_timestamp := max({ts |
		some a in v02_with_timestamp
		ts := _build_finished_on(a)
	})
	some att in v02_with_timestamp
	_build_finished_on(att) == max_v02_timestamp
]

latest_v1_pipelinerun_attestation := [pipelinerun_slsa_provenance_v1[0]] if {
	# If there's only one v1.0 attestation, return it regardless of timestamp
	count(pipelinerun_slsa_provenance_v1) == 1
} else := [att |
	# Multiple v1.0 attestations - filter by timestamp and return latest
	v1_with_timestamp := [a |
		some a in pipelinerun_slsa_provenance_v1
		_build_finished_on(a)
	]

	# make sure all v1.0 attestations have a timestamp
	count(v1_with_timestamp) == count(pipelinerun_slsa_provenance_v1)

	# Find the latest v1.0 attestation
	max_v1_timestamp := max({ts |
		some a in v1_with_timestamp
		ts := _build_finished_on(a)
	})
	some att in v1_with_timestamp
	_build_finished_on(att) == max_v1_timestamp
]

pipelinerun_slsa_provenance02 := [att |
	some att in input.attestations
	_is_pipelinerun_v02(att)
]

# TODO: Make this work with pipelinerun_attestations above so policy rules can be
# written for either.
pipelinerun_slsa_provenance_v1 := [att |
	some att in input.attestations
	_is_pipelinerun_v1_attestation(att)
]

_is_pipelinerun_v02(att) if {
	att.statement.predicate.buildType in _allowed_provenance_build_types
}

_is_pipelinerun_v1_attestation(att) if {
	att.statement.predicateType == slsa_provenance_predicate_type_v1
	build_type := att.statement.predicate.buildDefinition.buildType
	build_type in _allowed_provenance_build_types

	# Exclude attestations that are identifiably TaskRun attestations (have runSpec
	# with task keys but no pipeline keys). Everything else passes through: PipelineRun
	# attestations (runSpec with pipelineRef/pipelineSpec), non-Tekton attestations
	# (no runSpec at all), and malformed attestations (caught by downstream rules).
	_is_pipelinerun_v1(att)
}

is_pipelinerun_attestation(att) if {
	_is_pipelinerun_v02(att)
}

is_pipelinerun_attestation(att) if {
	_is_pipelinerun_v1_attestation(att)
}

default _is_pipelinerun_v1(_) := true

_is_pipelinerun_v1(att) := false if {
	spec_keys := object.keys(att.statement.predicate.buildDefinition.externalParameters.runSpec)
	pipeline_keys := {"pipelineRef", "pipelineSpec"}
	count(pipeline_keys - spec_keys) == count(pipeline_keys)
}

# These ones we don't care about any more
taskrun_attestations := [att |
	some att in input.attestations

	att.statement.predicate.buildType in taskrun_att_build_types
]

tasks_from_attestations(attestations) := [task |
	some att in attestations
	some task in tekton.tasks(att)
]

tasks_from_pipelinerun := tasks_from_attestations(pipelinerun_attestations)

# Signature-verified ITS PipelineRun associations before retry selection or
# Tekton task trust is applied.
_all_associated_its_pipelineruns contains associated if {
	some associated in intoto.associated_statement_provenances_by_predicate(intoto.predicate_test_result)
	_statement_subject_matches_image(associated.statement)
	is_pipelinerun_attestation(associated.provenance)
}

# Keep only PipelineRun associations whose test-result statement was selected
# by the shared latest-per-integration-test helper.
_latest_associated_its_pipelineruns contains associated if {
	statements := {candidate.statement | some candidate in _all_associated_its_pipelineruns}
	latest_statements := latest_test_attestations(statements)
	some associated in _all_associated_its_pipelineruns
	associated.statement in latest_statements
}

# PipelineRun provenance produced by ITS for the latest test-result statement
# of each integration test, after task trust is applied.
its_pipelinerun_attestations contains provenance if {
	some associated in _latest_associated_its_pipelineruns
	associated in intoto.verified_statement_provenances
	provenance := associated.provenance
}

tasks_from_its_pipelineruns := tasks_from_attestations(its_pipelinerun_attestations)

# Latest ITS PipelineRun provenance whose signature and statement subject were
# verified, before Tekton task trust is applied. This view distinguishes a
# missing required test task from one that ran in an untrusted latest retry.
associated_its_pipelinerun_attestations contains provenance if {
	some associated in _latest_associated_its_pipelineruns
	provenance := associated.provenance
}

tasks_from_associated_its_pipelineruns := tasks_from_attestations(associated_its_pipelinerun_attestations)

task_names_from_tasks(tasks) := {name |
	some task in tasks
	some name in tekton.task_names(task)
}

# All normalized task names discovered across the build and latest ITS runs.
build_pipelinerun_task_names := task_names_from_tasks(tasks_from_pipelinerun)

its_pipelinerun_task_names := task_names_from_tasks(tasks_from_its_pipelineruns)

associated_its_pipelinerun_task_names := task_names_from_tasks(tasks_from_associated_its_pipelineruns)

# Presence discovery includes each integration test's latest signature-verified
# ITS PipelineRun before task trust. The tasks policy separately rejects required
# test tasks whose execution did not pass task-trust validation.
discovered_task_names := build_pipelinerun_task_names | associated_its_pipelinerun_task_names

_statement_subject_matches_image(statement) if {
	some subject in object.get(statement, "subject", [])
	input.image.digest in intoto.subject_digests(subject)
}

# Collect all unique bundle references from tasks in the pipelineRun attestation.
# Returns a set of bundle refs that can be passed to ec.oci.image_manifests.
pipelinerun_bundle_refs contains ref if {
	some task in tasks_from_pipelinerun
	ref := tekton.task_ref(task).bundle
	ref != ""
}

# All results from the attested PipelineRun with the provided name. Results are
# expected to contain a JSON value. The return object contains the following
# keys:
#   name: name of the task in which the result appears.
#   name: Tekton bundle image reference for the corresponding task.
#   value: unmarshalled task result.
results_named(name) := [r |
	some task in tasks_from_pipelinerun
	some result in tekton.task_results(task)
	result.name == name
	result_map := unmarshal(result.value)

	# Inject the task data, currently task name and task bundle image
	# reference so we can show it in failure messages
	r := object.union({"value": result_map}, tekton.task_data(task))
]

# Attempts to json.unmarshal the given value. If not possible, the given
# value is returned as is. This is helpful when interpreting certain values
# in attestations created by Tekton Chains.
unmarshal(raw) := value if {
	json.is_valid(raw)
	value := json.unmarshal(raw)
} else := raw

# (Don't call it test_results since test_ means a unit test)
# First find results using the new task result name
results_from_tests := results_named(task_test_result_name)

# param_values expands the value into a list of values as needed. This is useful when handling
# parameters that could be of type string or an array of strings.
param_values(value) := {value} if {
	is_string(value)
} else := values if {
	is_array(value)
	values := {v | some v in value}
} else := values if {
	is_object(value)
	values := {v | some v in value}
}

# result_values expands the value of the given result into a list of values. This is useful when
# handling results that could be of type string, array of strings, or an object.
result_values(result) := value if {
	result.type == "string"
	value := {result.value}
} else := value if {
	result.type == "array"
	value := {v | some v in result.value}
} else := value if {
	result.type == "object"
	value := {v | some v in result.value}
}

attestation_materials(att) := att.statement.predicate.buildDefinition.resolvedDependencies if {
	# slsa v1 attestations
	att.statement.predicateType == slsa_provenance_predicate_type_v1
} else := att.statement.predicate.materials if {
	# slsa v0.2 attestations
	att.statement.predicateType == slsa_provenance_predicate_type_v02
} else := {}
