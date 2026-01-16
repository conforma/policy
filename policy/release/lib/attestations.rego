package lib

import rego.v1

import data.lib.tekton

slsa_provenance_predicate_type_v1 := "https://slsa.dev/provenance/v1"

slsa_provenance_predicate_type_v02 := "https://slsa.dev/provenance/v0.2"

tekton_pipeline_run := "tekton.dev/v1/PipelineRun"

pipelinerun_att_build_types := {
	tekton_pipeline_run,
	# Legacy build types
	"tekton.dev/v1beta1/PipelineRun",
	"https://tekton.dev/attestations/chains/pipelinerun@v2",
}

tekton_slsav1_pipeline_run := "https://tekton.dev/chains/v2/slsa-tekton"

slsav1_pipelinerun_att_build_types := {
	"https://tekton.dev/chains/v2/slsa",
	tekton_slsav1_pipeline_run,
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
	# Fallback to SLSA v1.0 path if v0.2 doesn't exist
	timestamp := att.statement.predicate.runDetails.metadata.buildFinishedOn
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
	att.statement.predicate.buildType in pipelinerun_att_build_types
]

# TODO: Make this work with pipelinerun_attestations above so policy rules can be
# written for either.
pipelinerun_slsa_provenance_v1 := [att |
	some att in input.attestations
	att.statement.predicateType == slsa_provenance_predicate_type_v1

	att.statement.predicate.buildDefinition.buildType in slsav1_pipelinerun_att_build_types

	# TODO: Workaround to distinguish between taskrun and pipelinerun attestations
	spec_keys := object.keys(att.statement.predicate.buildDefinition.externalParameters.runSpec)

	pipeline_keys := {"pipelineRef", "pipelineSpec"}

	count(pipeline_keys - spec_keys) != count(pipeline_keys)
]

# These ones we don't care about any more
taskrun_attestations := [att |
	some att in input.attestations

	att.statement.predicate.buildType in taskrun_att_build_types
]

tasks_from_pipelinerun := [task |
	some att in pipelinerun_attestations
	some task in tekton.tasks(att)
]

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
