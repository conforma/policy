# Rego Implementation Changes for New Trusted Tasks Format

## Overview

This document shows the Rego code changes needed to implement the new trusted tasks format, comparing three approaches:

1. **Option 1 – Complex Format (`new_acceptable_bundles.yaml`)**  
   Nested objects, multi-array iteration, and per-section logic.  
2. **Option 2 – Simplified Format**  
   Flatter `allowed_tasks` / `denied_tasks` arrays, but still separate sections.  
3. **Option 3 – Unified Rule List (Recommended)**  
   Single rule list with `action`, `pattern`, and optional fields; flat iteration and shared helpers.

---

## Option 1: Complex `new_acceptable_bundles.yaml` Format

*(Unchanged from previous draft — nested `allow` / `deny` objects with `task_refs`, `versions`, etc.)*  
See original section for code and schema.

---

## Option 2: Recommended Simplified Format (Prior Proposal)

*(Flattened `allowed_tasks` / `denied_tasks` lists, string-encoded version constraints)*  
See previous section for full YAML and Rego examples.

---

## Option 3: Unified Rule List Format (Recommended for Maintainability)

### **Data Format**

```yaml
trusted_task_rules:
  - action: "allow"
    pattern: "oci://quay.io/konflux-ci/tekton-catalog/*"
    effective_on: "2024-01-01T00:00:00Z"

  - action: "allow"
    pattern: "git+https://github.com/konflux-ci/build-definitions.git//*"
    effective_on: "2024-01-01T00:00:00Z"

  - action: "deny"
    pattern: "oci://quay.io/konflux-ci/tekton-catalog/task-buildah"
    versions: ["<0.5"]
    effective_on: "2025-11-15T00:00:00Z"

  - action: "deny"
    pattern: "oci://quay.io/konflux-ci/tekton-catalog/task-buildah"
    versions: ["<0.5.1"]
    effective_on: "2025-11-29T00:00:00Z"

  - action: "deny"
    pattern: "oci://quay.io/konflux-ci/tekton-catalog/task-foo"
    versions: [">=2", "<2.1.0"]
    effective_on: "2025-10-30T00:00:00Z"

  - action: "allow"
    pattern: "oci://quay.io/konflux-ci/tekton-catalog/*"
    signing_key: "<common public key>"
    effective_on: "2026-01-01T00:00:00Z"

### **Rego Implementation***
```Rego
package policy.lib.tekton

# Merge data
_rules_raw := object.union(data.trusted_task_rules, lib_rule_data("trusted_task_rules"))
_rules := cond(is_array(_rules_raw), _rules_raw, _rules_raw.rules)

# Partition rules
allow_rules := [r | r := _rules[_]; lower(r.action) == "allow"]
deny_rules  := [r | r := _rules[_]; lower(r.action) == "deny"]

# --- Entry point ---
is_trusted_task(task) {
  ref := task_ref(task)
  some rec in trusted_task_records(ref.key)
  rec.ref == ref.pinned_ref
} or {
  ref := task_ref(task)
  is_allowed(ref) and not is_denied(ref)
}

# --- Evaluation ---
is_allowed(ref) {
  some r in allow_rules
  pattern_matches(r.pattern, ref.key)
  rule_effective(r)
  versions_ok(r, ref)
  signing_ok(r, ref)
}

is_denied(ref) {
  some r in deny_rules
  pattern_matches(r.pattern, ref.key)
  rule_effective(r)
  versions_ok(r, ref)
}

# --- Helpers ---
pattern_matches(pattern, key) { glob.match(pattern, ["/"], key) }

rule_effective(r) {
  not r.effective_on
} or { time.parse_rfc3339_ns(r.effective_on) <= time.now_ns() }

signing_ok(r, ref) {
  not r.signing_key
} or { task_signed_with_key(ref.key, r.signing_key) }

versions_ok(r, ref) {
  not r.versions
} or {
  v := extract_version(ref.key)
  every c in r.versions { semver_satisfies(v, c) }
}

# --- Version extraction ---
extract_version(ref_key) := v if {
  startswith(ref_key, "oci://")
  v := oci_tag(ref_key)
} else := v if {
  startswith(ref_key, "git+")
  v := git_rev(ref_key)
} else := "" { true }

oci_tag(ref_key) := tag if {
  stripped := trim_prefix(ref_key, "oci://")
  base := split(stripped, "@")[0]
  idxs := indices(base, ":")
  count(idxs) > 0
  last := idxs[count(idxs)-1]
  tag := substring(base, last+1, -1)
} else := "latest" {
  stripped := trim_prefix(ref_key, "oci://")
  not contains(stripped, ":")
}

git_rev(ref_key) := rev if {
  parts := split(ref_key, "@")
  count(parts) >= 2
  rev := parts[count(parts)-1]
}

# --- Semver helpers ---
semver_satisfies(v, constraint) {
  cs := split(trim(constraint, " "), ",")
  every c in cs { semver_satisfies_one(v, trim(c, " ")) }
}

semver_satisfies_one(v, c) {
  startswith(c, "<="); req := trim_prefix(c, "<="); semver_cmp(v, req) <= 0
} or { startswith(c, "<");  req := trim_prefix(c, "<");  semver_cmp(v, req) <  0 }
  or { startswith(c, ">="); req := trim_prefix(c, ">="); semver_cmp(v, req) >= 0 }
  or { startswith(c, ">");  req := trim_prefix(c, ">");  semver_cmp(v, req) >  0 }
  or { startswith(c, "=");  req := trim_prefix(c, "=");  semver_cmp(v, req) == 0 }
  or { not re_match(`^(<=|<|>=|>|=)`, c); semver_cmp(v, c) == 0 }

semver_cmp(v, req) := out {
  vp := semver_parts(v); rp := semver_parts(req)
  out := cmp3(vp[0], rp[0]); out != 0
} else := out {
  vp := semver_parts(v); rp := semver_parts(req)
  out := cmp3(vp[1], rp[1]); out != 0
} else := out {
  vp := semver_parts(v); rp := semver_parts(req)
  out := cmp3(vp[2], rp[2])
} else := 0 { true }

semver_parts(s) := [maj, min, pat] {
  numeric := re_match(`^\d+(\.\d+){0,2}$`, s)
  parts := cond(numeric, split(s, "."), ["0","0","0"])
  maj := to_number(parts[0])
  min := to_number(cond(count(parts) > 1, parts[1], "0"))
  pat := to_number(cond(count(parts) > 2, parts[2], "0"))
}

cmp3(a, b) := -1 { a < b }; cmp3(a, b) := 1 { a > b }; cmp3(a, b) := 0 { a == b }

trim_prefix(s, p) := out { startswith(s, p); out := substring(s, count(p), -1) } else := s { true }

indices(s, sep) := [i |
  segs := split(s, sep)
  some n
  n > 0
  n < count(segs)
  i := sum([len(segs[j]) + len(sep) | j := 0; j < n]) - len(sep)
]
```

### **Key Simplicity Gains**

| **Aspect** | **Complex Format** | **Unified Rule List Format** | **Reduction / Improvement** |
|-------------|--------------------|------------------------------|------------------------------|
| **Schema depth** | 3 levels (`allow` / `deny` / `task_refs`) | 2 levels (single list) | ✅ Flatter |
| **Loops** | 2–3 nested loops per section | 1 flat loop per section | ✅ Simpler |
| **Duplicated code** | Repeated logic for `allow` + `deny` | Shared helpers | ✅ DRY |
| **Version checks** | Different meaning per section | Uniform semantics | ✅ Consistent |
| **Optional fields** | Different per section | Same across all | ✅ Predictable |
| **Adding new feature** | Add to both sections | Add once | ✅ Maintainable |
| **Testing surface** | Must test each section separately | One shape | ✅ Smaller matrix |
| **Extensibility** | Schema-dependent logic | Field-driven logic | ✅ Future-proof |

---

### **Summary**

The **Unified Rule List Format (Option 3)** provides the cleanest long-term approach:

- ✅ One consistent schema (`action`, `pattern`, optional fields)  
- ✅ Flat Rego iteration — easy to read, reason about, and test  
- ✅ Single point of extension for new fields  
- ✅ Lower cyclomatic complexity and maintenance overhead  
- ✅ Fewer implicit behaviors (each field always means the same thing)

**Conclusion:**  
From a Rego maintainer’s perspective, **Option 3** is the most maintainable, extensible, and least error-prone design.  
It keeps the policy authoring model consistent and the Rego logic predictable,  
with no duplicated or nested iteration paths.
