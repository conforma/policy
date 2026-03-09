package provenance_materials_test

import rego.v1

import data.lib
import data.lib.assertions
import data.lib.tekton_test
import data.provenance_materials

test_all_good if {
	tasks := [{
		"results": [
			{"name": "url", "value": _git_url},
			{"name": "commit", "value": _git_commit},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	assertions.assert_empty(provenance_materials.deny) with input.attestations as [_mock_attestation_v02(tasks)]
	assertions.assert_empty(provenance_materials.deny) with input.attestations as [_mock_attestation_v1(tasks)]
}

test_normalized_git_url if {
	tasks := [{
		"results": [
			{"name": "url", "value": concat("", ["git+", _git_url, ".git"])},
			{"name": "commit", "value": _git_commit},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	assertions.assert_empty(provenance_materials.deny) with input.attestations as [_mock_attestation_v02(tasks)]
	assertions.assert_empty(provenance_materials.deny) with input.attestations as [_mock_attestation_v1(tasks)]
}

test_missing_git_clone_task if {
	tasks := [{
		"results": [
			{"name": "spam", "value": "maps"},
			{"name": "eggs", "value": "sgge"},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "provenance_materials.git_clone_task_found",
		"msg": "Task git-clone not found",
	}}

	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v02(tasks)]
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v1(tasks)]
}

test_scattered_results if {
	tasks := [
		{
			"results": [{"name": "url", "value": _git_url}],
			"ref": {"bundle": _bundle},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
		{
			"results": [{"name": "commit", "value": _git_commit}],
			"ref": {"bundle": _bundle},
			"steps": [{"entrypoint": "/bin/bash"}],
		},
	]

	expected := {{
		"code": "provenance_materials.git_clone_task_found",
		"msg": "Task git-clone not found",
	}}

	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v02(tasks)]
}

test_missing_materials if {
	tasks := [{
		"results": [
			{"name": "url", "value": _git_url},
			{"name": "commit", "value": _git_commit},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "provenance_materials.git_clone_source_matches_provenance",
		"msg": `Entry in materials for the git repo "git+https://gitforge/repo.git" and commit "9d25f3b6ab8cfba5d2d68dc8d062988534a63e87" not found`, # regal ignore:line-length
	}}

	# v0.2: remove materials
	missing_materials_v02 := json.remove(_mock_attestation_v02(tasks), ["/statement/predicate/materials"])
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [missing_materials_v02]

	# v1.0: remove only the git material from resolvedDependencies (keep task dependencies)
	good_attestation_v1 := _mock_attestation_v1(tasks)

	# Remove the last item in resolvedDependencies which is the git material
	deps_count := count(good_attestation_v1.statement.predicate.buildDefinition.resolvedDependencies)
	missing_materials_v1 := json.remove(
		good_attestation_v1,
		[sprintf(
			"/statement/predicate/buildDefinition/resolvedDependencies/%d",
			[deps_count - 1],
		)],
	)
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [missing_materials_v1]
}

test_commit_mismatch if {
	tasks := [{
		"results": [
			{"name": "url", "value": _git_url},
			{"name": "commit", "value": _bad_git_commit},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "provenance_materials.git_clone_source_matches_provenance",
		# regal ignore:line-length
		"msg": `Entry in materials for the git repo "git+https://gitforge/repo.git" and commit "b10a8c637a91f427576eb0a4f39f1766c7987385" not found`,
	}}
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v02(tasks)]
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v1(tasks)]
}

test_url_mismatch if {
	tasks := [{
		"results": [
			{"name": "url", "value": _bad_git_url},
			{"name": "commit", "value": _git_commit},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "provenance_materials.git_clone_source_matches_provenance",
		"msg": concat(
			" ",
			[
				"Entry in materials for the git repo",
				`"git+https://shady/repo.git"`,
				"and commit",
				`"9d25f3b6ab8cfba5d2d68dc8d062988534a63e87" not found`,
			],
		),
	}}
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v02(tasks)]
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v1(tasks)]
}

test_commit_and_url_mismatch if {
	tasks := [{
		"results": [
			{"name": "url", "value": _bad_git_url},
			{"name": "commit", "value": _bad_git_commit},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}]

	expected := {{
		"code": "provenance_materials.git_clone_source_matches_provenance",
		# regal ignore:line-length
		"msg": `Entry in materials for the git repo "git+https://shady/repo.git" and commit "b10a8c637a91f427576eb0a4f39f1766c7987385" not found`,
	}}
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v02(tasks)]
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation_v1(tasks)]
}

test_provenance_many_git_clone_tasks if {
	task := {
		"results": [
			{"name": "url", "value": _git_url},
			{"name": "commit", "value": _git_commit},
		],
		"ref": {"bundle": _bundle},
		"steps": [{"entrypoint": "/bin/bash"}],
	}

	task1 := json.patch(task, [{
		"op": "add",
		"path": "name",
		"value": "git-clone-1",
	}])

	task2 := json.patch(task, [{
		"op": "add",
		"path": "name",
		"value": "git-clone-2",
	}])

	attestation_v02 := _mock_attestation_v02([task1, task2])

	# all good
	assertions.assert_empty(provenance_materials.deny) with input.attestations as [attestation_v02]

	attestation_v1 := _mock_attestation_v1([task1, task2])
	assertions.assert_empty(provenance_materials.deny) with input.attestations as [attestation_v1]

	# one task's cloned digest doesn't match
	expected := {{
		"code": "provenance_materials.git_clone_source_matches_provenance",
		# regal ignore:line-length
		"msg": `Entry in materials for the git repo "git+https://gitforge/repo.git" and commit "big-bada-boom" not found`,
	}}

	# v0.2: patch buildConfig/tasks
	# regal ignore:line-length
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [json.patch(attestation_v02, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/0/results/1/value",
		"value": "big-bada-boom",
	}])]

	# v1.0: patch resolvedDependencies (need to decode, modify, re-encode)
	v1_bad_commit := json.patch(attestation_v1, [{
		"op": "replace",
		"path": "/statement/predicate/buildDefinition/resolvedDependencies/0/content",
		"value": base64.encode(json.marshal(json.patch(
			json.unmarshal(base64.decode(attestation_v1.statement.predicate.buildDefinition.resolvedDependencies[0].content)),
			[{
				"op": "replace",
				"path": "/status/results/1/value",
				"value": "big-bada-boom",
			}],
		))),
	}])
	assertions.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [v1_bad_commit]
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_git_url := "https://gitforge/repo"

_bad_git_url := "https://shady/repo"

_git_commit := "9d25f3b6ab8cfba5d2d68dc8d062988534a63e87"

_bad_git_commit := "b10a8c637a91f427576eb0a4f39f1766c7987385"

_mock_attestation_v02(original_tasks) := d if {
	default_task := {
		"name": "git-clone",
		"ref": {"kind": "Task"},
	}

	tasks := [task |
		some original_task in original_tasks
		task := object.union(default_task, original_task)
	]

	d := {"statement": {
		"predicateType": "https://slsa.dev/provenance/v0.2",
		"predicate": {
			"buildType": lib.tekton_pipeline_run,
			"buildConfig": {"tasks": tasks},
			"materials": [{
				"uri": sprintf("git+%s.git", [_git_url]),
				"digest": {"sha1": _git_commit},
			}],
		},
	}}
}

# Helper to create SLSA v1.0 attestation with git materials
_mock_attestation_v1(original_tasks) := att if {
	# Create v1.0 tasks from the input tasks (similar structure to v0.2 but v1.0 format)
	tasks := [v1_task |
		some original_task in original_tasks
		task_name := object.get(original_task, "name", "git-clone")
		results := object.get(original_task, "results", [])
		bundle := object.get(original_task, ["ref", "bundle"], _bundle)

		_task_base := tekton_test.slsav1_task(task_name)
		_task_w_bundle := tekton_test.with_bundle(_task_base, bundle)
		v1_task := tekton_test.with_results(_task_w_bundle, results)
	]

	# Create base attestation
	base_att := tekton_test.slsav1_attestation(tasks)

	# Add git materials to resolvedDependencies
	git_material := {
		"uri": sprintf("git+%s.git", [_git_url]),
		"digest": {"sha1": _git_commit},
	}

	att := json.patch(base_att, [{
		"op": "add",
		"path": "/statement/predicate/buildDefinition/resolvedDependencies/-",
		"value": git_material,
	}])
}
