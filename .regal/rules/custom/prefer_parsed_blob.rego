# METADATA
# description: |
#   Prefer oci.parsed_blob(ref) over json.unmarshal(ec.oci.blob(ref)).
#   The parsed_blob wrapper centralizes blob parsing and will use a cached
#   builtin (ec.oci.parsed_blob) once available, avoiding redundant
#   json.unmarshal calls across policy namespace evaluations.
# related_resources:
#   - description: EC-1836
#     ref: https://redhat.atlassian.net/browse/EC-1836
# schemas:
#   - input:
#       ref: github.com/open-policy-agent/regal#input
# custom:
#   category: custom
package custom.regal.rules.custom["prefer-parsed-blob"]

import rego.v1

import data.regal.result

report contains violation if {
	some i, line in input.regal.file.lines
	trimmed := trim_space(line)
	not startswith(trimmed, "#")
	contains(line, "json.unmarshal")
	contains(line, "ec.oci.blob")

	loc := object.union(result.location(input.rules[0]), {"location": {
		"col": 1,
		"row": i + 1,
		"text": line,
	}})
	violation := result.fail(rego.metadata.chain(), loc)
}
