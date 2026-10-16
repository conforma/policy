# Trusted-Task Grandfathering

Trusted-task deny rules sometimes need to block new builds immediately without
invalidating artifacts that were completed before the rule took effect. The
existing metadata `effective_on` behavior cannot express this: it delays the
rule globally, including for new builds, and the CLI owns its warning-to-denial
transition.

## Why grandfathering belongs in task trust

Several release rules depend on whether a task is trusted. Applying an
exception in an individual result helper would make the outcome depend on which
rule reported the failure. Instead, attestation-aware callers use one shared
trust decision. This keeps build-task checks, required-task checks, scripted
build checks, and in-toto provenance verification consistent.

Pipeline-definition checks intentionally remain strict. They have no signed
build completion timestamp, so they cannot prove that an artifact predates a
cutoff.

## Time model

A deny record may pair its existing `effective_on` cutoff with an absolute
`grandfather_until` deadline:

```yaml
deny:
  deprecated-task:
    - pattern: oci://registry.example/task:old-*
      effective_on: 2026-10-01T00:00:00Z
      grandfather_until: 2026-11-01T00:00:00Z
```

After `effective_on`, the deny is waived only when the signed SLSA provenance
says the build completed strictly before the cutoff and evaluation occurs
strictly before `grandfather_until`. SLSA v1 uses
`runDetails.metadata.finishedOn`; SLSA v0.2 uses
`metadata.buildFinishedOn`.

The fixed deadline avoids a rolling grace period: repeatedly evaluating an old
artifact never extends its eligibility. At the cutoff, at the deadline, with a
missing or malformed timestamp, or with invalid configuration, trust fails
closed.

When multiple effective deny records match, every one must grandfather the
attestation. A single immediate, expired, or otherwise ineligible deny remains
authoritative. This preserves deny precedence across overlapping rule-data
groups.

## Operator visibility

The trusted-task release package emits a warning as soon as an eligible deny
record is present, including before `effective_on`. It includes the task,
matching pattern, cutoff, and fixed deadline so teams see the real date when
the same build will become a violation. The ordinary future-deny warning is
suppressed for that record because its cutoff is not the artifact's deadline.
