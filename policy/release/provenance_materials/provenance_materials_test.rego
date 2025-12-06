package provenance_materials_test

import rego.v1

import data.lib
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

	lib.assert_empty(provenance_materials.deny) with input.attestations as [_mock_attestation(tasks)]
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

	lib.assert_empty(provenance_materials.deny) with input.attestations as [_mock_attestation(tasks)]
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

	lib.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation(tasks)]
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

	lib.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation(tasks)]
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
	good_attestation := _mock_attestation(tasks)
	missing_materials := json.remove(good_attestation, ["/statement/predicate/materials"])

	expected := {{
		"code": "provenance_materials.git_clone_source_matches_provenance",
		# regal ignore:line-length
		"msg": `Entry in materials for the git repo "git+https://gitforge/repo.git" and commit "9d25f3b6ab8cfba5d2d68dc8d062988534a63e87" not found`,
	}}
	lib.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [missing_materials]
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
	lib.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation(tasks)]
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
	lib.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation(tasks)]
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
	lib.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [_mock_attestation(tasks)]
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

	attestation := _mock_attestation([task1, task2])

	# all good
	lib.assert_empty(provenance_materials.deny) with input.attestations as [attestation]

	# one task's cloned digest doesn't match
	expected := {{
		"code": "provenance_materials.git_clone_source_matches_provenance",
		# regal ignore:line-length
		"msg": `Entry in materials for the git repo "git+https://gitforge/repo.git" and commit "big-bada-boom" not found`,
	}}
	lib.assert_equal_results(expected, provenance_materials.deny) with input.attestations as [json.patch(attestation, [{
		"op": "replace",
		"path": "/statement/predicate/buildConfig/tasks/0/results/1/value",
		"value": "big-bada-boom",
	}])]
}

_bundle := "registry.img/spam@sha256:4e388ab32b10dc8dbc7e28144f552830adc74787c1e2c0824032078a79f227fb"

_git_url := "https://gitforge/repo"

_bad_git_url := "https://shady/repo"

_git_commit := "9d25f3b6ab8cfba5d2d68dc8d062988534a63e87"

_bad_git_commit := "b10a8c637a91f427576eb0a4f39f1766c7987385"

_mock_attestation(original_tasks) := d if {
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
