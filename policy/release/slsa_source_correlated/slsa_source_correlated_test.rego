package slsa_source_correlated_test

import rego.v1

import data.lib
import data.slsa_source_correlated

test_deny_missing_source_code_happy_day if {
	lib.assert_empty(slsa_source_correlated.deny) with input.image as {"source": {"something": "here"}}
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref")]
}

test_deny_missing_expected_source_code_reference if {
	attestations := [_source_material_attestation("git+https://git.repository", "ref")]
	expected := {{
		"code": "slsa_source_correlated.source_code_reference_provided",
		"msg": "Expected source code reference was not provided for verification",
	}}
	lib.assert_equal_results(slsa_source_correlated.deny, expected) with input as {}
		with input.attestations as attestations
	lib.assert_equal_results(slsa_source_correlated.deny, expected) with input.image as {}
		with input.attestations as attestations
	lib.assert_equal_results(slsa_source_correlated.deny, expected) with input.image as {"source": {}}
		with input.attestations as attestations
}

test_deny_material_code_reference if {
	# no source materials
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.attested_source_code_reference",
		"msg": "The attested material contains no source code reference",
	}}) with input.image as expected
		with input.attestations as [_material_attestation([]), _resolved_dependencies_attestation([])]

	# unsupported scm SLSA Provenance v0.2
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.attested_source_code_reference",
		"msg": "The attested material contains no source code reference",
	}}) with input.image as expected
		with input.attestations as [_source_material_attestation("xyz+https://some.repository", "ref")]

	# unsupported scm SLSA Provenance v1.0
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.attested_source_code_reference",
		"msg": "The attested material contains no source code reference",
	}}) with input.image as expected
		with input.attestations as [_source_resolved_dependencies_attestation("xyz+https://some.repository", "ref")]
}

# regal ignore:rule-length
test_deny_expected_source_code_reference_happy_day if {
	# one material matches expected SLSA Provenance v0.2
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref")]

	# one material matches expected SLSA Provenance v1.0
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [_source_resolved_dependencies_attestation("git+https://git.repository", "ref")]

	dependencies := [
		{
			"uri": "registry.io/repository/image",
			"digest": {"sha256": "cafe000000000000000000000000000000000000000000000000000000cafe00"},
		},
		{
			"uri": "git+https://git.repository",
			"digest": {"sha1": "ref"},
		},
		{
			"uri": "registry.io/repository/image2",
			"digest": {"sha256": "dada000000000000000000000000000000000000000000000000000000dada00"},
		},
	]

	# more than one material, one matches expected the others are unrelated
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [
			_material_attestation(dependencies),
			_resolved_dependencies_attestation(dependencies),
		]

	# more than one material, one matches expected the other doesn't, this is,
	# currently not a failure SLSA Provenance v0.2
	#
	# TODO: most likely we want to distinguish what source was built from what
	# source references were used by the build
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [
			_source_material_attestation("git+https://git.repository", "ref"),
			_source_material_attestation("git+https://unexpected.repository", "unexpected"),
		]

	# more than one material, one matches expected the other doesn't, this is,
	# currently not a failure SLSA Provenance v1.0
	#
	# TODO: most likely we want to distinguish what source was built from what
	# source references were used by the build
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [
			_source_resolved_dependencies_attestation("git+https://git.repository", "ref"),
			_source_material_attestation("git+https://unexpected.repository", "unexpected"),
		]

	# the `gitCommit` support as digest algorithm in SLSA Provenance v1.0
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [_resolved_dependencies_attestation([{
			"uri": "git+https://git.repository",
			"digest": {"gitCommit": "ref"},
			"name": "inputs/result",
		}])]

	# missing .git suffix in input.image.source.git.url SLSA Provenance v0.2
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://git.repository.git", "ref")]

	# missing .git in predicate.materials.uri of SLSA Provenance v0.2
	img1 = {"source": {"git": {"url": "https://git.repository.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img1
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref")]

	# extra .git suffix in input.image.source.git.url SLSA Provenance v0.2
	img2 = {"source": {"git": {"url": "https://git.repository.git.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img2
		with input.attestations as [_source_material_attestation("git+https://git.repository.git", "ref")]

	# extra .git suffix in predicate.materials.uri SLSA Provenance v0.2
	img3 = {"source": {"git": {"url": "https://git.repository.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img3
		with input.attestations as [_source_material_attestation("git+https://git.repository.git.git", "ref")]

	# missing .git suffix in input.image.source.git.url SLSA Provenance v1.0
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [_source_resolved_dependencies_attestation("git+https://git.repository.git", "ref")]

	# missing .git in predicate.resolvedDependencies.uri of SLSA Provenance v1.0
	img4 = {"source": {"git": {"url": "https://git.repository.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img4
		with input.attestations as [_source_resolved_dependencies_attestation("git+https://git.repository", "ref")]

	# extra .git suffix in input.image.source.git.url SLSA Provenance v1.0
	img5 = {"source": {"git": {"url": "https://git.repository.git.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img5
		with input.attestations as [_source_resolved_dependencies_attestation("git+https://git.repository.git", "ref")]

	# extra .git suffix in predicate.resolvedDependencies.uri SLSA Provenance
	# v0.2
	img6 = {"source": {"git": {"url": "https://git.repository.git", "revision": "ref"}}}
	att1 = _source_resolved_dependencies_attestation("git+https://git.repository.git.git", "ref")
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img6
		with input.attestations as [att1]

	# missing .git suffix in input.image.source.git.url SLSA Provenance v1.0, gitCommit support
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [_resolved_dependencies_attestation([{
			"uri": "git+https://git.repository.git",
			"digest": {"gitCommit": "ref"},
			"name": "inputs/result",
		}])]

	# missing .git in predicate.resolvedDependencies.uri of SLSA Provenance
	# v1.0, gitCommit support
	img7 = {"source": {"git": {"url": "https://git.repository.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img7
		with input.attestations as [_resolved_dependencies_attestation([{
			"uri": "git+https://git.repository",
			"digest": {"gitCommit": "ref"},
			"name": "inputs/result",
		}])]

	# extra .git suffix in input.image.source.git.url SLSA Provenance v1.0,
	# gitCommit support
	img8 = {"source": {"git": {"url": "https://git.repository.git.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img8
		with input.attestations as [_resolved_dependencies_attestation([{
			"uri": "git+https://git.repository.git",
			"digest": {"gitCommit": "ref"},
			"name": "inputs/result",
		}])]

	# extra .git suffix in predicate.resolvedDependencies.uri SLSA Provenance
	# v0.2, gitCommit support
	img9 = {"source": {"git": {"url": "https://git.repository.git", "revision": "ref"}}}
	lib.assert_empty(slsa_source_correlated.deny) with input.image as img9
		with input.attestations as [_resolved_dependencies_attestation([{
			"uri": "git+https://git.repository.git.git",
			"digest": {"gitCommit": "ref"},
			"name": "inputs/result",
		}])]
}

# regal ignore:rule-length
test_deny_expected_source_code_reference_v02 if {
	# different scm SLSA Provenance v0.2
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
		"term": "svn+https://git.repository@sha1:ref",
	}}) with input.image as expected
		with input.attestations as [_source_material_attestation("svn+https://git.repository", "ref")]

	# different repository SLSA Provenance v0.2
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
		"term": "git+https://unexpected.repository@sha1:ref",
	}}) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://unexpected.repository", "ref")]

	# different revision SLSA Provenance v0.2
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
		"term": "git+https://git.repository@sha1:unexpected",
	}}) with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://git.repository", "unexpected")]

	# multiple mismatches SLSA Provenance v0.2
	lib.assert_equal_results(slsa_source_correlated.deny, {
		{
			"code": "slsa_source_correlated.expected_source_code_reference",
			"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
			"term": "git+https://git.repository@sha1:unexpected",
		},
		{
			"code": "slsa_source_correlated.expected_source_code_reference",
			"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
			"term": "git+https://unexpected.repository@sha1:ref",
		},
		{
			"code": "slsa_source_correlated.expected_source_code_reference",
			"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
			"term": "svn+https://git.repository@sha1:ref",
		},
	}) with input.image as expected
		with input.attestations as [
			_source_material_attestation("svn+https://git.repository", "ref"),
			_source_material_attestation("git+https://unexpected.repository", "ref"),
			_source_material_attestation("git+https://git.repository", "unexpected"),
		]

	# missing source revision in input.image SLSA Provenance v0.2
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": `The expected source code reference "git+https://git.repository@" is not attested`,
		"term": "git+https://git.repository@sha1:ref",
	}}) with input.image as {"source": {"git": {"url": "https://git.repository"}}}
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref")]

	# missing source url in input.image SLSA Provenance v0.2
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": `The expected source code reference "git+@ref" is not attested`,
		"term": "git+https://git.repository@sha1:ref",
	}}) with input.image as {"source": {"git": {"revision": "ref"}}}
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref")]
}

# regal ignore:rule-length
test_deny_expected_source_code_reference_v10 if {
	# different scm SLSA Provenance v1.0
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
		"term": "svn+https://git.repository@sha1:ref",
	}}) with input.image as expected
		with input.attestations as [_source_resolved_dependencies_attestation("svn+https://git.repository", "ref")]

	# different repository SLSA Provenance v1.0
	att1 = _source_resolved_dependencies_attestation("git+https://unexpected.repository", "ref")
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
		"term": "git+https://unexpected.repository@sha1:ref",
	}}) with input.image as expected
		with input.attestations as [att1]

	# different revision SLSA Provenance v1.0
	att2 = _source_resolved_dependencies_attestation("git+https://git.repository", "unexpected")
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
		"term": "git+https://git.repository@sha1:unexpected",
	}}) with input.image as expected
		with input.attestations as [att2]

	# multiple mismatches SLSA Provenance v1.0
	lib.assert_equal_results(slsa_source_correlated.deny, {
		{
			"code": "slsa_source_correlated.expected_source_code_reference",
			"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
			"term": "git+https://git.repository@sha1:unexpected",
		},
		{
			"code": "slsa_source_correlated.expected_source_code_reference",
			"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
			"term": "git+https://unexpected.repository@sha1:ref",
		},
		{
			"code": "slsa_source_correlated.expected_source_code_reference",
			"msg": "The expected source code reference \"git+https://git.repository@ref\" is not attested",
			"term": "svn+https://git.repository@sha1:ref",
		},
	}) with input.image as expected
		with input.attestations as [
			_source_resolved_dependencies_attestation("svn+https://git.repository", "ref"),
			_source_resolved_dependencies_attestation("git+https://unexpected.repository", "ref"),
			_source_resolved_dependencies_attestation("git+https://git.repository", "unexpected"),
		]

	# missing source revision in input.image SLSA Provenance v1.0
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": `The expected source code reference "git+https://git.repository@" is not attested`,
		"term": "git+https://git.repository@sha1:ref",
	}}) with input.image as {"source": {"git": {"url": "https://git.repository"}}}
		with input.attestations as [_source_resolved_dependencies_attestation("git+https://git.repository", "ref")]

	# missing source url in input.image SLSA Provenance v1.0
	lib.assert_equal_results(slsa_source_correlated.deny, {{
		"code": "slsa_source_correlated.expected_source_code_reference",
		"msg": `The expected source code reference "git+@ref" is not attested`,
		"term": "git+https://git.repository@sha1:ref",
	}}) with input.image as {"source": {"git": {"revision": "ref"}}}
		with input.attestations as [_source_resolved_dependencies_attestation("git+https://git.repository", "ref")]
}

test_slsa_v02_source_references if {
	lib.assert_empty(slsa_source_correlated._source_references)
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [_material_attestation([])]
	att1 = _source_material_attestation("https://something:somewhere", "cafe")
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att1]

	# no digest
	att2 = _material_attestation([{"uri": "git+https://git.repository"}])
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att2]

	# unsupported digest algorithm
	att3 = _material_attestation([{"uri": "git+https://git.repository", "digest": {"md2": "unsupported"}}])
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att3]

	# no uri
	att4 = _material_attestation([{"digest": {"sha256": "cafe000000000000000000000000000000000000000000000000000000cafe00"}}])
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att4]
	lib.assert_equal(
		{"git+ssh://git.repository@sha1:cafe"},
		slsa_source_correlated._source_references,
	) with input.attestations as [_source_material_attestation("git+ssh://git.repository", "cafe")]
	lib.assert_equal(
		{"git+ssh://git.repository@sha1:cafe", "hg+https://hg.repository@sha1:dada"},
		slsa_source_correlated._source_references,
	) with input.attestations as [
		_source_material_attestation("git+ssh://git.repository", "cafe"),
		_source_material_attestation("hg+https://hg.repository", "dada"),
	]
}

# regal ignore:rule-length
test_slsa_v10_source_references if {
	att1 = _resolved_dependencies_attestation([])
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att1]
	att2 = _source_resolved_dependencies_attestation("https://something:somewhere", "cafe")
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att2]

	# no digest
	att3 = _resolved_dependencies_attestation([{"uri": "git+https://git.repository"}])
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att3]

	# unsupported digest algorithm
	att4 = _resolved_dependencies_attestation([{
		"uri": "git+https://git.repository",
		"digest": {"md2": "unsupported"},
	}])
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att4]

	# no uri
	att5 = _resolved_dependencies_attestation([{"digest": {"sha256": "cafe000000000000000000000000000000000000000000000000000000cafe00"}}])
	lib.assert_empty(slsa_source_correlated._source_references) with input.attestations as [att5]
	lib.assert_equal(
		{"git+ssh://git.repository@sha1:cafe"},
		slsa_source_correlated._source_references,
	) with input.attestations as [_source_resolved_dependencies_attestation("git+ssh://git.repository", "cafe")]
	lib.assert_equal(
		{"git+ssh://git.repository@sha1:cafe", "hg+https://hg.repository@sha1:dada"},
		slsa_source_correlated._source_references,
	) with input.attestations as [
		_source_resolved_dependencies_attestation("git+ssh://git.repository", "cafe"),
		_source_resolved_dependencies_attestation("hg+https://hg.repository", "dada"),
	]
}

test_slsa_v02_ignore_irrelevant_attestations if {
	good_att := _source_material_attestation("git+https://git.repository", "ref")
	irrelevant_att := _material_attestation([])
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [good_att, irrelevant_att]
}

test_slsa_v10_ignore_irrelevant_attestations if {
	good_att := _source_resolved_dependencies_attestation("git+https://git.repository", "ref")
	irrelevant_att := _resolved_dependencies_attestation([])
	lib.assert_empty(slsa_source_correlated.deny) with input.image as expected
		with input.attestations as [good_att, irrelevant_att]
}

test_rule_data_provided if {
	d := {
		"supported_digests": [
			# Wrong type
			1,
			# Duplicated items
			"sha1",
			"sha1",
		],
		# We don't need to check the different errors for each key as they are processed the same
		# way. But we do want to, at least, verify a single error.
		"supported_vcs": [1, "git"],
	}

	violations := {
		{
			"code": "slsa_source_correlated.rule_data_provided",
			"msg": "Rule data supported_digests has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
		{
			"code": "slsa_source_correlated.rule_data_provided",
			"msg": "Rule data supported_digests has unexpected format: (Root): array items[1,2] must be unique",
			"severity": "failure",
		},
		{
			"code": "slsa_source_correlated.rule_data_provided",
			"msg": "Rule data supported_vcs has unexpected format: 0: Invalid type. Expected: string, given: integer",
			"severity": "failure",
		},
	}

	lib.assert_equal_results(slsa_source_correlated.deny, violations) with data.rule_data as d
		with input.image as expected
		with input.attestations as [_source_material_attestation("git+https://git.repository", "ref")]
}

test_refs if {
	some provided, expected in {
		{"https://git.repository": "rev"}: {
			"https://git.repository@sha1:rev",
			"https://git.repository.git@sha1:rev",
			"https://git.repository@gitCommit:rev",
			"https://git.repository.git@gitCommit:rev",
		},
		{"https://git.repository.git": "rev"}: {
			"https://git.repository.git@sha1:rev",
			"https://git.repository.git.git@sha1:rev",
			"https://git.repository@sha1:rev",
			"https://git.repository.git@gitCommit:rev",
			"https://git.repository.git.git@gitCommit:rev",
			"https://git.repository@gitCommit:rev",
		},
		{"https://git.repository/": "rev"}: {
			"https://git.repository/@sha1:rev",
			"https://git.repository/.git@sha1:rev",
			"https://git.repository@sha1:rev",
			"https://git.repository.git@sha1:rev",
			"https://git.repository/@gitCommit:rev",
			"https://git.repository/.git@gitCommit:rev",
			"https://git.repository@gitCommit:rev",
			"https://git.repository.git@gitCommit:rev",
		},
	}

	some uri, revision in provided

	lib.assert_equal(slsa_source_correlated._refs(uri, revision), expected)
}

expected := {"source": {"git": {"url": "https://git.repository", "revision": "ref"}}}

# SLSA Provenance v0.2
_material_attestation(materials) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v0.2",
	"predicate": {
		"buildType": lib.tekton_pipeline_run,
		"materials": materials,
	},
}}

# SLSA Provenance v0.2
_source_material_attestation(uri, sha1) := _material_attestation([{
	"uri": uri,
	"digest": {"sha1": sha1},
}])

# SLSA Provenance v1.0
_resolved_dependencies_attestation(dependencies) := {"statement": {
	"predicateType": "https://slsa.dev/provenance/v1",
	"predicate": {"buildDefinition": {
		"buildType": "https://tekton.dev/chains/v2/slsa",
		"externalParameters": {"runSpec": {"pipelineSpec": {}}},
		"resolvedDependencies": dependencies,
	}},
}}

# SLSA Provenance v1.0
_source_resolved_dependencies_attestation(uri, sha1) := _resolved_dependencies_attestation([{
	"uri": uri,
	"digest": {"sha1": sha1},
	"name": "inputs/result",
}])
