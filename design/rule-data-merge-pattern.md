# Rule Data Merge Pattern

Merging data-source values with ruleData configuration values using `object.union`.
Used by `pipeline_required_tasks` and `trusted_tasks` in `policy/lib/tekton/`.

## Why does `rule_data.get()` need an explicit `{}` default for merged keys?

`rule_data.get(key)` falls back to `[]` (empty array) when a key isn't found in any
data source. But `object.union` requires both arguments to be objects — if either is
an array, OPA returns `undefined` at runtime (see next section). So any key that will
be passed to `object.union` must have an explicit `{}` default registered in the
`defaults` map in `policy/lib/rule_data/rule_data.rego`. Without it, the merge silently
produces `undefined` and all downstream rules stop evaluating with no error output.

When adding a new `object.union` merge, register the key in rule_data.rego's `defaults`:

```rego
defaults := {
    "pipeline-required-tasks": {},  # must be {} not [] for object.union
    "trusted_tasks": {},            # same reason
    ...
}
```

## Why does `object.union` fail silently instead of erroring?

OPA has two behaviors depending on when it can determine types:

- **Static types known** (literals in code): `object.union({"a": 1}, [])` produces a
  compile-time `rego_type_error` — policy fails to load.
- **Dynamic types from `data`** (the common case): both arguments are typed `any`, so
  OPA skips compile-time checking. At runtime, `object.union` with a non-object argument
  returns `undefined` — no error, no diagnostic. The rule becomes undefined and all
  consumers silently skip it.

This means a misconfigured data source that provides an array instead of an object will
cause policy rules to silently stop evaluating, producing zero violations and zero errors.
The `{}` default in rule_data.rego is the primary defense against this.

## How does the override precedence work in the merge?

`object.union(A, B)` gives B full override for matching keys. In the merge pattern:

```rego
pipeline_required_tasks := object.union(data["pipeline-required-tasks"], rule_data.get("pipeline-required-tasks"))
```

- A = `data["pipeline-required-tasks"]` (from data sources)
- B = `rule_data.get(...)` which checks, in priority order:
  1. `data.rule_data__configuration__` (ECP policy ruleData)
  2. `data.rule_data_custom` (custom user sources)
  3. `data.rule_data` (default data sources)
  4. `defaults` map (hardcoded `{}`)

When B has a matching selector key (e.g. `"docker"`), it replaces A's value entirely —
the arrays are not merged. This is intentional and matches the trusted_tasks precedent.
