package trusted_task

import rego.v1

import data.lib
import data.lib.image
import data.lib.tekton

# create rule matchers for the following rules format:
#     trusted_task_rules:
#     allow:
#         - name: "rule name"
#           pattern: "oci://quay.io/konflux-ci/tekton-catalog/*"
#           versions: [">0.1", "<=0.5"]     # optional
#           effective_on: 2025-11-15        # optional
#           expires_on: 2026-11-15          # optional
#           signing_key: abcde              # optional (require if set)
#         - ...
#     deny:
#         - name: "rule name"
#           pattern: "oci://quay.io/konflux-ci/tekton-catalog/task-buildah"
#           versions: ["<0.3"]              # optional
#           effective_on: 2025-11-15        # optional
#           expires_on: 2026-11-15          # optional
#         - ...
get_rule_matchers(task_rules) := matchers {
	matchers := {
		"allow": [matcher |
			some rule in task_rules.allow
			matcher := _create_matcher(rule)
		],
		"deny": [matcher |
			some rule in task_rules.deny
			matcher := _create_matcher(rule)
		],
	}
}

# _create_matcher builds a matcher object from a rule
_create_matcher(rule) := matcher if {
	_is_rule_active(rule) # create matcher only if the rule is currently active

    matcher := {
		"name": rule.name,
		"pattern": rule.pattern,
	}

	# Add optional fields if present
	matcher := object.union(matcher, {"versions": rule.versions} if "versions" in object.keys(rule) else {})
	matcher := object.union(matcher, {"signing_key": rule.signing_key} if "signing_key" in object.keys(rule) else {})
}

# _is_rule_active checks if a rule is currently active based on effective_on and expires_on dates
_is_rule_active(rule) := is_active {
	now := time.now_ns()

	# Check effective_on if present
	effective_ok := true if not "effective_on" in object.keys(rule)
	else time.parse_rfc3339_ns(sprintf("%sT00:00:00Z", [rule.effective_on])) <= now

	# Check expires_on if present
	expires_ok := true if not "expires_on" in object.keys(rule)
	else time.parse_rfc3389_ns(sprintf("%sT00:00:00Z", [rule.expires_on])) > now

	is_active := effective_ok and expires_ok
}

# is_task_allowed determines if a task is allowed based on allow and deny rules
# A task is allowed if:
# - it matches at least one active allow rule
# - it doesn't match any active deny rules
is_task_allowed(task, task_rules) {
	matchers := get_rule_matchers(task_rules)

	# Task must match at least one allow rule
	some allow_matcher in matchers.allow
	_task_matches_rule(task, allow_matcher)

	# Task must not match any deny rules
	not _task_matches_any_deny_rule(task, matchers.deny)
}

# _task_matches_any_deny_rule checks if task matches any deny rule
_task_matches_any_deny_rule(task, deny_matchers) {
	some deny_matcher in deny_matchers
	_task_matches_rule(task, deny_matcher)
}

# _task_matches_rule checks if a task matches a specific rule matcher
_task_matches_rule(task, matcher) {

	# Task ref must match pattern
	regex.match(matcher.pattern, task.ref)

	# If rule has versions constraint, task version must satisfy it
	_version_matches(task.version, matcher)

	# If rule has signing_key requirement, task signing_key must match
	_signing_key_matches(task, matcher)
}

# _version_matches checks if task version satisfies rule version constraints
_version_matches(task_version, matcher) {
	not "versions" in object.keys(matcher)
}

_version_matches(task_version, matcher) {
	"versions" in object.keys(matcher)
	every version_constraint in matcher.versions {
		_satisfies_version_constraint(task_version, version_constraint)
	}
}

# _signing_key_matches checks if task signing key matches rule requirement
_signing_key_matches(task, matcher) {
	not "signing_key" in object.keys(matcher)
}

_signing_key_matches(task, matcher) {
	"signing_key" in object.keys(matcher)
	task.signing_key == matcher.signing_key
}

# _satisfies_version_constraint checks if a version satisfies a constraint like ">0.1" or "<=0.5"
_satisfies_version_constraint(version, constraint) {
	# Parse constraint operator and value
	# This is a placeholder - you'll need to implement version comparison logic
	# based on your version format and comparison requirements
	true  # TODO: Implement actual version constraint checking
}