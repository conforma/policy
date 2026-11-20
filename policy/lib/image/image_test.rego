package lib.image_test

import rego.v1

import data.lib.assertions
import data.lib.image

# regal ignore:rule-length
test_parse if {
	repository := "registry.com/re/po"
	repository_with_port := "registry.com:8443/re/po"
	local_repository := "localhost:9000/re/po"
	tag := "latest"
	digest := "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"

	assertions.assert_equal(
		image.parse(concat("", [repository, ":", tag, "@", digest])),
		{"repo": repository, "tag": tag, "digest": digest},
	)

	assertions.assert_equal(
		image.parse(concat("", [repository, "@", digest])),
		{"repo": repository, "tag": "", "digest": digest},
	)

	assertions.assert_equal(
		image.parse(concat("", [repository, ":", tag])),
		{"repo": repository, "tag": tag, "digest": ""},
	)

	assertions.assert_equal(
		image.parse(concat("", [repository_with_port, ":", tag, "@", digest])),
		{"repo": repository_with_port, "tag": tag, "digest": digest},
	)

	assertions.assert_equal(
		image.parse(concat("", [repository_with_port, "@", digest])),
		{"repo": repository_with_port, "tag": "", "digest": digest},
	)

	assertions.assert_equal(
		image.parse(concat("", [repository_with_port, ":", tag])),
		{"repo": repository_with_port, "tag": tag, "digest": ""},
	)

	assertions.assert_equal(
		image.parse(concat("", [repository_with_port, ":", tag, " "])),
		{"repo": repository_with_port, "tag": tag, "digest": ""},
	)
	assertions.assert_equal(
		image.parse(concat("", [local_repository, ":", tag, "@", digest])),
		{"repo": local_repository, "tag": tag, "digest": digest},
	)
}

test_not_parse if {
	tag := "latest"
	digest := "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
	not image.parse(concat("", ["http://not-a-registry.com", ":", tag, "@", digest]))
	not image.parse("oci://not-a-registry.com")
	not image.parse("operator-sdk-v1.32.0")
	not image.parse("quay.io")
}

test_equal if {
	image.equal_ref("registry.com/re/po", "registry.com/re/po")
	image.equal_ref("registry.com/re/po:tag", "registry.com/re/po:tag")
	image.equal_ref("registry.com/re/po:tag@digest", "registry.com/re/po:tag@digest")
	image.equal_ref("registry.com/re/po:different@digest", "registry.com/re/po:tag@digest")
	image.equal_ref("registry.com/re/po@digest", "registry.com/re/po:tag@digest")
	image.equal_ref("registry.com/re/po:tag@digest", "registry.com/re/po@digest")
	not image.equal_ref("registry.com/re/po", "different.com/re/po")
	not image.equal_ref("registry.com/different/po", "registry.com/re/po")
	not image.equal_ref("registry.com/re/different", "registry.com/re/po")
	not image.equal_ref("registry.com/re/po:different", "registry.com/re/po:tag")
	not image.equal_ref("registry.com/re/po:tag@different", "registry.com/re/po:tag@digest")
	not image.equal_ref("registry.com/re/po@different", "registry.com/re/po:tag@digest")
	not image.equal_ref("registry.com/re/po:tag@different", "registry.com/re/po@digest")
	not image.equal_ref("registry.com/re/po@different", "registry.com/re/po@digest")
	not image.equal_ref("registry.com/re/po@digest", "different.com/re/po@digest")
	not image.equal_ref("registry.com/re/po@digest", "registry.com/different/po@digest")
	not image.equal_ref("registry.com/re/po@digest", "registry.com/re/different@digest")
}

test_str if {
	assertions.assert_equal(
		"registry.io/repository:tag@digest",
		image.str({"repo": "registry.io/repository", "tag": "tag", "digest": "digest"}),
	)
	assertions.assert_equal(
		"registry.io/repository:tag",
		image.str({"repo": "registry.io/repository", "tag": "tag"}),
	)
	assertions.assert_equal(
		"registry.io/repository@digest",
		image.str({"repo": "registry.io/repository", "digest": "digest"}),
	)
}

test_is_image_index if {
	ref := "registry.io/repository:tag@digest"

	image_index := {"mediaType": "application/vnd.oci.image.index.v1+json"}
	image.is_image_index(ref) with ec.oci.descriptor as image_index

	manifest_list := {"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json"}
	image.is_image_index(ref) with ec.oci.descriptor as manifest_list

	image_manifest := {"mediaType": "application/vnd.oci.image.manifest.v1+json"}
	not image.is_image_index(ref) with ec.oci.descriptor as image_manifest

	not image.is_image_index(ref) with ec.oci.descriptor as {}

	not image.is_image_index(ref) with ec.oci.descriptor as false
}

# G43: syntax validation is independent of parse/equal_ref's existing contract.
test_valid_digest if {
	every pair in [["sha256", 64], ["sha384", 96], ["sha512", 128], ["blake3", 64]] {
		encoded := concat("", ["a" | some _ in numbers.range(1, pair[1])])
		image.valid_digest(sprintf("%s:%s", [pair[0], encoded]))
		not image.valid_digest(sprintf("%s:%s", [pair[0], substring(encoded, 1, -1)]))
		not image.valid_digest(sprintf("%s:%s0", [pair[0], encoded]))
		not image.valid_digest(sprintf("%s:%s", [pair[0], upper(encoded)]))
		not image.valid_digest(sprintf("%s:%s", [pair[0], replace(encoded, "a", "g")]))
	}
	every digest in ["multihash+base58:QmRZxt2b1F", "sha256+b64u:LCa0a2j_xo_5m0U8HTBBNBNCLXBkg7-g-YpeiGJm564"] {
		image.valid_digest(digest)
	}
	every digest in [null, 1, true, {}, [], "", "not-a-digest", "sha256:", ":abc", "sha256:ab:cd", "sha256:abc@def", "SHA256:abc", "sha256+:abc", "sha256:abc def"] {
		not image.valid_digest(digest)
	}
}

test_is_pinned if {
	digest := "sha256:01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b"
	every ref in [sprintf("registry.local/task:1.0@%s", [digest]), sprintf("localhost:5000/repo/task@%s", [digest]), sprintf(" registry.local/task@%s ", [digest])] {
		image.is_pinned(ref)
	}
	every ref in [null, 1, true, {}, [], "", "registry.local/task:1.0", "registry.local/task:1.0@", "registry.local/task:1.0@not-a-digest", "registry.local/task:1.0@sha256:", sprintf("registry.local/task@%s@extra", [digest]), sprintf("http://registry.local/task@%s", [digest])] {
		not image.is_pinned(ref)
	}
}
