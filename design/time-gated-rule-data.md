# Time-Gated Rule Data

Rule data entries with `effective_on` dates allow gradual rollout of policy requirements. The `ectime` library resolves which entry applies now (`most_current`) and which is newest regardless of date (`newest`). Several packages use this pattern: `required_tasks`, `test_attestation`, and their release-side counterparts.

## How do `most_current` and `newest` differ in failure behavior?

`newest` sorts entries by `effective_on` as a string and picks the last one. It almost always succeeds for non-empty input — it doesn't parse or validate dates. `most_current` parses each `effective_on` with `time.parse_rfc3339_ns`, filters to entries not in the future, then calls `newest` on that filtered set. It is undefined when all entries are in the future.

This asymmetry matters: checking `not ectime.newest(data)` is almost never true when data exists, so it's not a useful guard on its own. The meaningful existence check is whether the resolution path produces an entry with the expected fields (e.g., `.tests` or `.tasks`).

## Why do consumer helpers need `default` values?

Rego's `not X in Y` requires `Y` to be defined. If `Y` is undefined, Rego tries to bind `Y` before evaluating the `in` expression, and the undefined binding causes the entire rule body to fail — `not` does not rescue it. This means helpers consumed by rules that use `in` or `some ... in` must always be defined.

Use `default _helper := []` (not `else := []`) to provide the fallback. `default` is the canonical Rego mechanism for ensuring a rule always has a value. `else := []` works but conflates "couldn't resolve" with "resolved to empty," making existence checks on the same helper unreliable.

## What is the pattern for adding new time-gated rule data?

Follow the separation used by `required_tasks` and `test_attestation`:

1. **Consumer helpers** — always defined via `default`, safe for `in` expressions:
   ```rego
   default _current_required_items := []
   _current_required_items := entry.items if {
       entry := ectime.most_current(_rule_data)
   }
   ```

2. **Existence checks** — undefined-based boolean helpers (no default/else) for deny/warn guards:
   ```rego
   _resolved_required_items if {
       ectime.most_current(_rule_data).items
   }
   _resolved_required_items if {
       ectime.newest(_rule_data).items
   }
   ```

3. **Deny rule** — checks data exists but resolution fails:
   ```rego
   deny contains result if {
       count(_rule_data) > 0
       not _resolved_required_items
       ...
   }
   ```

The boolean helper uses two rule bodies (OR): it's true if either current or newest resolves to an entry with the expected field. The deny fires only when data was provided but neither path produces a usable entry.
