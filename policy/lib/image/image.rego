package lib.image

import rego.v1

# is_pinned checks digest syntax without changing parse's permissive contract.
# Algorithm-specific encodings follow the OCI descriptor digest specification:
# https://github.com/opencontainers/image-spec/blob/main/descriptor.md#digests
is_pinned(ref) if {
	is_string(ref)
	parts := split(trim_space(ref), "@")
	count(parts) == 2
	parse(ref)
	valid_digest(parts[1])
}

# valid_digest accepts OCI digest grammar and validates the length and lowercase
# hex encoding of known algorithms. Unrecognized algorithms retain OCI's
# extensible encoding grammar; this checks syntax, not content integrity.
valid_digest(digest) if {
	is_string(digest)
	regex.match(`^[a-z0-9]+(?:[+._-][a-z0-9]+)*:[A-Za-z0-9=_-]+$`, digest)
	parts := split(digest, ":")
	_valid_digest_encoding(parts[0], parts[1])
}

_digest_lengths := {"sha256": 64, "sha384": 96, "sha512": 128, "blake3": 64}

_valid_digest_encoding(algorithm, encoded) if {
	count(encoded) == _digest_lengths[algorithm]
	regex.match(`^[a-f0-9]+$`, encoded)
}

_valid_digest_encoding(algorithm, _) if {
	not algorithm in object.keys(_digest_lengths)
}

# parse returns a data structure representing the different portions
# of the OCI image reference.
parse(ref) := d if {
	trimmed_ref := trim_space(ref)

	# Note: This regex is simplified and does not cover all valid hostname cases.
	# It only matches hostnames in the form of <hostname><optional port><optional path>.
	# For example "registry.com", "registry.com/repo", "localhost:5000/repo/subrepo"
	# It does not include all subdomains and does not support Unicode.
	regex.match(`^([A-Za-z0-9.-]+(?::[0-9]+)?)(?:\/.*)?$`, trimmed_ref)

	# a valid repo will contain a /
	contains(trimmed_ref, "/")

	digest_parts := split(trimmed_ref, "@")

	repo_parts := split(digest_parts[0], "/")

	tag_parts := split(repo_parts[count(repo_parts) - 1], ":")
	count(tag_parts) <= 2
	tag := _get(tag_parts, 1, "")

	repo := concat(
		"/",
		array.concat(
			array.slice(repo_parts, 0, count(repo_parts) - 1),
			[tag_parts[0]],
		),
	)

	digest := _get(digest_parts, 1, "")

	d := {
		"digest": digest,
		"repo": repo,
		"tag": tag,
	}
}

# Formats the parsed reference as string
str(d) := s1 if {
	d.repo != ""
	d.digest != ""
	d.tag != ""
	s1 := sprintf("%s:%s@%s", [d.repo, d.tag, d.digest])
} else := s2 if {
	d.repo != ""
	d.digest != ""
	s2 := sprintf("%s@%s", [d.repo, d.digest])
} else := s3 if {
	d.repo != ""
	d.tag != ""
	s3 := sprintf("%s:%s", [d.repo, d.tag])
}

# equal_ref returns true if two image references point to the same image. The
# algorithm first checks if the constituent parts repository, tag and digest are
# all equal
equal_ref(ref1, ref2) if {
	img1 := parse(ref1)
	img2 := parse(ref2)

	img1 == img2
}

# equal_ref returns true if two image references point to the same image,
# ignoring the tag. This complements the case where all parts of the reference
# need to be equal.
equal_ref(ref1, ref2) if {
	img1 := parse(ref1)

	# need to make sure that the digest of one reference is present, otherwise we
	# might end up comparing image references without tags and digests. equal_ref is
	# commutative, so we can check that the digest exists for one of the references,
	# in this case img1
	img1.digest != ""

	img2 := parse(ref2)
	object.remove(img1, ["tag"]) == object.remove(img2, ["tag"])
}

_get(ary, index, default_value) := value if {
	value := ary[index]
} else := default_value

# Returns a value if the reference is for an Image Index.
is_image_index(ref) if {
	ec.oci.descriptor(ref).mediaType in {
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}
}
