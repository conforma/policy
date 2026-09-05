# Threat Model: conforma/policy

## 1. System Context

The policy repo contains OPA/Rego rules that the Conforma CLI evaluates to
gate software supply chain releases in Konflux. It does not run independently.
The CLI fetches policy bundles from an OCI registry, loads them into an
embedded OPA engine, and evaluates them against attestation data attached to
container images.

```
                     +-----------+
                     | OCI       |
                     | Registry  |
                     +-----+-----+
                           |
            policy bundle  |  attestations, SBOMs, images
                           |
        +------------------v------------------+
        |          Conforma CLI (ec)           |
        |   +-------------------------------+ |
        |   | OPA Engine                    | |
        |   |  +-------------------------+  | |
        |   |  | conforma/policy (Rego)  |  | |
        |   |  | + rule_data + config    |  | |
        |   |  +-------------------------+  | |
        |   +-------------------------------+ |
        +------------------+------------------+
                           |
                     pass / fail
```

The policy rules receive inputs from two sources:

1. **`input.*`**: attestation statements, image references, and verification
   results injected by the CLI after signature/attestation verification.
2. **`data.*`**: rule data, trusted task lists, sigstore configuration, and
   volatile config assembled by the CLI from the EnterpriseContractPolicy (ECP)
   data sources, ruleData fields, and CLI config structs.

The rules generally do not perform signature or attestation verification
themselves. The CLI handles that before evaluation, and the rules assume
`input.attestations` contains already-verified (or explicitly skip-verified)
statements. The `test` and `test_attestation` packages instead use
`lib/intoto`'s `verified_statements` path to perform their own
sigstore+trusted-task chain-of-trust checks on in-toto referrers. The `tasks`
package also uses `lib/intoto` to discover signature-verified test-result
provenance, select the latest PipelineRun for each integration test by
`configuration[0].name` and `timestamp`, and then enforce task trust (see
section 3.1).

### Evaluation contexts

Policy evaluation occurs at two gates in Konflux:

- **Integration testing** (post-build): developer controls the
  IntegrationTestScenario and which ECP is referenced. Policy violations are
  surfaced but the developer influences the configuration.
- **Release gating** (pre-release): the ReleasePlanAdmission in a managed
  namespace (controlled by SRE/releng) specifies the ECP. The developer cannot
  modify the release-gate policy configuration.

The same Rego code runs at both gates. The difference is who controls the
`data.*` tree.

### Relationship to the CLI threat model

The CLI threat model ([conforma/cli THREAT_MODEL.md](https://github.com/conforma/cli/blob/main/THREAT_MODEL.md),
EC-2001) covers how data enters the system: CLI flags, signature verification,
OCI downloads, server mode, Kubernetes API interactions. This document covers
what the Rego rules do with that data once it arrives: how rules evaluate
inputs, where logic gaps can cause silent passes, and how the policy bundle
distribution chain can be compromised.

Where a threat spans both repos, this document focuses on the policy-side
implications and cross-references the CLI threat model for the CLI-side
controls.

## 2. Assets

| Asset | Description | Sensitivity |
|-------|-------------|-------------|
| **Policy rules** (88 non-test Rego files) | Deny/warn rules enforcing supply chain requirements: SLSA provenance, trusted tasks, CVE thresholds, base image registries, RPM signatures, SBOM validity, OLM compliance, hermetic builds. | Integrity: Critical. Tampered rules can silently pass non-compliant images. Availability: High. Unavailable rules block all releases. |
| **Shared libraries** (`policy/lib/`) | 18 library packages (oci, intoto, sigstore, rule_data, tekton, volatile, metadata, etc.) consumed by all policy rules. A bug in a library function affects every rule that calls it. | Integrity: Critical. |
| **Rule data defaults** (`lib/rule_data/rule_data.rego`) | Hardcoded fallback values for CVE severity thresholds, allowed predicate types, builder IDs, supported digests, trusted task config, OLM constraints. | Integrity: Critical. Weakened defaults change enforcement for any consumer not overriding them. |
| **OCI policy bundles** (`quay.io/conforma/*-policy`) | Built artifacts distributed to all Konflux clusters. Four bundles: release, pipeline, task, build_task. | Integrity: Critical. A compromised bundle affects every consumer. |
| **Rule metadata annotations** | OPA annotations on each rule (collections, effective_on, depends_on, short_name) controlling rule selection, time-gating, and reporting. | Integrity: High. Altered annotations can silently exclude rules from collections or defer enforcement indefinitely. |
| **Test fixtures and example data** | Sample attestations, snapshots, rule data used in unit tests and CI. | Integrity: Medium. Corrupted fixtures can mask failing tests. |

## 3. Entry Points and Trust Boundaries

### 3.1 Attestation data (`input.attestations`)

**Source**: SLSA provenance and other in-toto attestations attached to
container images, verified (or skip-verified) by the CLI before policy
evaluation.

**What the rules do**: Extract builder ID, task references, task results
(TEST_OUTPUT, RPMS_DATA, SOURCE_IMAGE_URL, etc.), build parameters, timestamps,
materials, and SBOM content. Nearly every deny/warn rule in `policy/release/`
consumes attestation fields. When multiple attestations of the same type exist,
`policy/release/lib/attestations.rego` selects the latest by `buildFinishedOn`
timestamp.

**Trust boundary**: The rules treat `input.attestations` as pre-verified by
the CLI. If the CLI's `--skip-att-sig-check` flag is used, unverified
attestation content flows into all rules that consume it. The `test` and
`test_attestation` packages use the independently verified `verified_statements`
path through `lib/intoto`. The `tasks` package uses both that trusted view and
the signature-verified `associated_statement_provenances` view to discover and
report test-task trust failures. Retry selection happens before task trust so an
older trusted run cannot mask an untrusted latest retry, and an older untrusted
run does not invalidate a trusted latest retry. Other packages consume
`input.attestations` directly.

See CLI threat model CA-3 for the CLI-side controls on signature skip flags.

### 3.2 Rule data (`data.rule_data*`)

**Source**: Assembled by the CLI from multiple origins with a 4-level
precedence cascade implemented in `lib/rule_data/rule_data.rego`:

| Priority | Source | Key namespace |
|----------|--------|---------------|
| 1 (highest) | ECP `sources[].ruleData` | `data.rule_data__configuration__` |
| 2 | User-provided custom data sources | `data.rule_data_custom` |
| 3 | Standard data sources (OCI/git) | `data.rule_data` |
| 4 (lowest) | Hardcoded in Rego | `lib.rule_data.defaults` |

If a key is not found at any level, `rule_data.get()` returns an empty list.

**Trust boundary**: At the release gate, the developer cannot modify
`rule_data__configuration__` (ECP-controlled). But they may influence
`rule_data_custom` or `rule_data` if the ECP references data sources they
can contribute to.

**Security-critical rule data keys** (non-exhaustive):

| Key | Effect if weakened |
|-----|---------------------|
| `trusted_tasks` / `trusted_task_rules` | Malicious task bundles treated as trusted |
| `allowed_registry_prefixes` | Base images from untrusted registries permitted |
| `allowed_builder_ids` | Builds from non-Tekton builders accepted |
| `restrict_cve_security_levels` | CVE blocking thresholds raised |
| `cve_leeway` | Unlimited grace period for known vulnerabilities |
| `allowed_predicate_types` | Non-SLSA attestation formats accepted |
| `allowed_rpm_signature_keys` | Unsigned or foreign-signed RPMs permitted |
| `pipeline_run_params` | Expected build parameters relaxed |
| `pipeline_intention` | Operational mode of certain rules changed |

### 3.3 Trusted task data (`data.trusted_tasks`, `data.trusted_task_rules`)

**Source**: OCI data bundles maintained by release engineering (e.g.,
`quay.io/konflux-ci/tekton-catalog/data-acceptable-bundles`), merged with
ruleData-provided `trusted_tasks` / `trusted_task_rules`.

**What the rules do**: `lib/tekton/trusted.rego` implements two systems.
The **rules system** (preferred) uses pattern-based allow/deny rules with glob
matching, semver version constraints, and `effective_on` dates. The **legacy
system** (being phased out) is a pure allowlist with expiry dates. The rules
system takes priority when data is present.

**Trust boundary**: The merge is additive. `_trusted_task_rules_data`
concatenates system-level rules (`data.trusted_task_rules`) with ruleData-level
rules (`rule_data.get("trusted_task_rules")`). An attacker who can add entries
to the ruleData-level data can expand the set of trusted tasks without
modifying the system-level data source. For allow rules, ALL version
constraints must be satisfied; for deny rules, ANY constraint suffices.

### 3.4 Sigstore configuration (`data.config.default_sigstore_opts`)

**Source**: Serialized by the CLI from its internal config structs into OPA's
data tree.

**What the rules do**: `lib/sigstore/sigstore.rego` exposes `sigstore.opts`
which defaults to safe values (empty strings, `ignore_rekor: false`) and is
overridden by `data.config.default_sigstore_opts` when present. Rules like
`source_image.signed` pass `sigstore.opts` to `ec.sigstore.verify_image`.

**Trust boundary**: The default covers 7 fields (`certificate_identity`,
`certificate_identity_regexp`, `certificate_oidc_issuer`,
`certificate_oidc_issuer_regexp`, `ignore_rekor`, `public_key`, `rekor_url`).
If additional fields can be injected via OPA deep merge from data sources,
sigstore verification behavior can be altered. See CLI threat model open
question 5 for the serialization gap analysis.

### 3.5 OCI blob fetching (`ec.oci.*` builtins)

**Source**: Rego rules call EC-specific builtins (`ec.oci.image_manifest`,
`ec.oci.blob`, `ec.oci.image_referrers`, `ec.oci.image_manifests`) to fetch
content from OCI registries at evaluation time.

**What the rules do**: Fetch task bundle manifests for trust verification,
source image manifests for existence checks, referrer lists for in-toto
statement discovery, and blob content for SBOM parsing.

**Trust boundary**: These builtins bypass OPA's network sandbox by design
(they need registry access). The content is fetched over TLS but the content
itself is attacker-influenced (the attacker controls their image, its layers,
and its referrers). Malformed OCI content (unexpected JSON structure, missing
fields) can cause rules to evaluate to undefined rather than deny.

### 3.6 Policy bundle distribution

**Source**: GitHub Actions workflow (`.github/workflows/push-bundles.yaml`)
builds policy bundles on push to main and publishes them to
`quay.io/enterprise-contract/` and `quay.io/conforma/` using `oras push`.
Registry credentials are stored in GitHub Secrets.

**Trust boundary**: There is no cosign signing step in the push workflow.
Bundles are pushed with `oras push` and tagged with `skopeo copy`, but the
resulting OCI artifacts are unsigned. Compromise of the push credentials, the
GitHub Actions workflow, or the quay.io namespace would allow shipping tampered
rules to all consumers.

Consumers can pin specific bundle digests via the EC Tekton task's
`POLICY_BUNDLE_DIGEST` parameter, which mitigates tag-mutation attacks. But
without signatures on the bundles themselves, there is no cryptographic proof
that a bundle at a given digest was produced by the legitimate build pipeline.

### 3.7 Volatile configuration (`data.config.policy`)

**Source**: The ECP's `spec.configuration` field, assembled by the CLI into
`data.config.policy`. Contains include/exclude lists and `volatileConfig`
(time-bounded rule exclusions).

**What the rules do**: `lib/volatile/volatile_config.rego` processes
`effectiveOn`/`effectiveUntil` dates to determine rule lifecycle state
(pending, no_expiration, expiring, expired, invalid). Rules can be scoped by
`imageRef`, `imageUrl`, `imageDigest`, `componentNames`, or applied globally.
The metadata library uses collection membership (from rule annotations) and
include/exclude lists to select which rules run.

**Trust boundary**: At the release gate, volatile config is SRE-controlled.
At the integration-test gate, the developer controls it. The `effective_time`
value used for date comparisons comes from the CLI's `--effective-time` flag,
which the developer can set at the integration gate. See CLI threat model CA-2
for the `--allow-past-effective-time` defense-in-depth control.

### 3.8 Image reference (`input.image.ref`)

**Source**: The image reference under evaluation, provided by the CLI from the
Snapshot.

**What the rules do**: `lib/intoto/trust.rego` passes `input.image.ref` to
`ec.oci.image_referrers()` to discover in-toto statement referrers.
`lib/volatile/volatile_config.rego` matches it against rule scope patterns.

**Trust boundary**: The image reference determines which OCI referrers are
fetched and which volatile config exclusions apply. In Konflux, the Snapshot is
created by the Integration Service from the Global Candidate List, not by the
developer. See CLI threat model IV-4 for the Snapshot trust model.

## 4. Threats

### 4.1 Input Evasion

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| IE-1 | **Silent pass on undefined evaluation**: crafted attestation content causes a rule to evaluate to undefined (neither deny nor warn), silently passing. In Rego, an unmet precondition produces no output rather than an explicit failure. | High: specific rules silently disabled. | Medium: requires understanding Rego evaluation semantics and specific rule data paths. | Some packages implement guard rules (`test_data_found`, `base_image_info_found`, `allowed_registries_provided`). Pattern is not universal across all 88 non-test Rego files. |
| IE-2 | **Attestation timestamp manipulation**: when multiple provenance statements exist for the same image, `policy/release/lib/attestations.rego` selects the latest by `buildFinishedOn`. An attacker who can attach additional attestations post-build could inject a fabricated newer attestation. | High: fabricated attestation used for evaluation instead of the legitimate one. | Low: Tekton Chains controls attestation generation, and the CLI should filter to verified attestations before policy evaluation. | Relies on CLI to provide only verified attestations. If `--skip-att-sig-check` is used, this mitigation disappears. |
| IE-3 | **Type confusion in task results**: task result values (TEST_OUTPUT, RPMS_DATA) with unexpected types or structure cause rule evaluation to skip rather than deny. | Medium: specific checks bypassed. | Medium: attacker controls build pipeline task results via PaC definitions. | Some rules validate result format (e.g., `rpm_signature.result_format`), but coverage is inconsistent across packages. |
| IE-4 | **Missing data treated as compliant**: empty or zero-value inputs treated as "no violations" rather than "data missing". Rego's default is to produce empty sets for deny/warn when predicates don't match. | High: entire rule category silently passes. | Medium: inherent to Rego's evaluation model. | Several rules have explicit "data found" prerequisites, but the pattern is not applied to all packages. |

### 4.2 Data Poisoning

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| DP-1 | **Rule data override via influenceable data source**: attacker adds permissive entries to `rule_data_custom` via a data source they can influence (e.g., a git repo referenced in the ECP). | High: weakens thresholds, expands trusted lists. | Low at release gate (SRE controls ECP and data sources), Medium at integration gate. | The `rule_data.get()` priority chain means `rule_data__configuration__` takes precedence. Custom data can only override if higher-priority keys are absent. |
| DP-2 | **Trusted task injection via ruleData merge**: attacker adds entries to ruleData-level `trusted_tasks` or `trusted_task_rules` to mark malicious task bundles as trusted. The merge in `lib/tekton/trusted.rego` is additive: ruleData entries are concatenated with system data. | Critical: malicious build tasks treated as trusted, undermining provenance guarantees. | Low at release gate (SRE controls ECP), Medium at integration gate. | Schema validation checks format but not semantic correctness of task references. The rules system supports deny rules that take precedence over allow rules, providing a mechanism for system-level blocks. |
| DP-3 | **Config namespace injection**: attacker injects new keys into `data.config.*` via OPA deep merge, adding fields not present in the CLI's config structs. | High: can alter sigstore verification behavior or introduce unexpected config. | Medium: requires the ECP to reference a data source the attacker can contribute to. | The CLI serializes a fixed set of config fields. OPA merge can only add new keys, not override existing ones. But any field consumed by a builtin but not serialized by the CLI becomes an injection vector. |
| DP-4 | **Unbounded numeric rule data**: attacker manipulates `cve_leeway` values or `task_expiry_warning_days` to grant extended grace periods. | High: known critical CVEs or expired tasks pass the release gate. | Low at release gate, Medium at integration gate. | Leeway computation trusts configured values without upper-bound enforcement. `task_expiry_warning_days` has schema validation for type (integer, minimum 0) but no maximum. |

### 4.3 Logic Errors

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| LE-1 | **Implicit pass from Rego semantics**: a rule with an unmet precondition produces no output, which OPA treats as "no violation". This is inherent to Rego's design and the primary logic-class risk. | High: silent pass for unexpected input shapes. | Medium: new rules are at risk of this unless the author explicitly follows the guard-rule pattern. | Some packages implement guard rules (e.g., `test_data_found`, `base_image_info_found`). Pattern is not formally documented or enforced by linting or CI. |
| LE-2 | **`effective_on` time manipulation**: rule annotations with `effective_on` dates cause new rules to be demoted from deny to warn until the date arrives. The CLI's `--effective-time` flag controls what "now" means. At the integration gate, the developer sets this. | Medium: time-gated security rules silently demoted. | Medium at integration gate, Low at release gate. | At the release gate, `EFFECTIVE_TIME` defaults to "now" and is controlled by the pipeline definition. `--allow-past-effective-time` defaults to false in the CLI. |
| LE-3 | **Collection membership gap**: rule collection membership is declared in OPA annotations. A rule accidentally omitted from a collection (e.g., `@redhat_security`) will never run when that collection is selected. | High: security rule silently excluded from enforcement. | Low: code review process exists, and the repo recently added 18 rules to `redhat_security`. | Collection stub packages exist for CI. Annotation consistency checked by `checks/annotations.rego`. No automated exhaustive check that every security-relevant deny rule is in the right collections. |
| LE-4 | **Trusted task rule precedence confusion**: deny rules take precedence in the rules system, but the interaction between system-level deny and ruleData-level allow is determined by concatenation order. Both are flattened into a single list in `_trusted_task_rules_data`. | Medium: ruleData allow rules could interact unexpectedly with system deny rules depending on pattern specificity. | Low: deny is checked first in `is_trusted_task_rules` (deny match blocks trust regardless of allow matches). | `_task_matches_deny_rule` is evaluated before `_task_matches_allow_rule`, so deny takes precedence. This is correct but not obviously documented. |

### 4.4 Supply Chain (Policy Bundle)

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| SC-1 | **Unsigned policy bundles**: bundles pushed to quay.io are not cosign-signed. There is no cryptographic proof that a bundle was produced by the legitimate GitHub Actions workflow. | Critical: consumers cannot verify bundle provenance. A compromised bundle affects every consumer. | Low: requires compromising CI credentials or the quay.io push secret. | `POLICY_BUNDLE_DIGEST` pin in EC Tekton task definitions allows digest pinning, which prevents tag-mutation attacks but does not prove provenance. Registry push requires authentication. |
| SC-2 | **Tag mutation**: attacker pushes a new image to a mutable tag (e.g., `:latest`) without changing the tag name. `update-bundles.sh` sets both a git-SHA tag and a `:latest` tag via `skopeo copy`. | Critical: consumers fetching by tag get attacker-controlled policy. | Low: requires quay.io push credentials. | Digest pinning via `POLICY_BUNDLE_DIGEST` mitigates if set. Tag-only references are vulnerable. |
| SC-3 | **Test fixture manipulation**: modified test fixtures in `example/data/` or inline test data cause CI to pass for rules that don't actually work correctly in production. | Medium: false confidence in rule correctness. | Low: requires commit access; PR review covers test changes. | 100% test coverage enforcement. Tests run network-isolated via `unshare -r -n` when available. |
| SC-4 | **Build tool dependency compromise**: the bundle build uses `go run github.com/conforma/cli` for OPA operations and `go run oras.land/oras/cmd/oras` for pushing. A compromised dependency affects bundle content or distribution. | High: tests pass with tampered evaluation engine, or bundles are silently altered during push. | Very Low: Go module system uses checksums (`go.sum`). | `go.sum` verifies downloaded bytes match recorded hashes, but does not establish publisher provenance or prevent a malicious update from being intentionally recorded. Dependency updates are automated via Renovate and require PR review before merging. |

### 4.5 Denial of Service

| ID | Threat | Impact | Likelihood | Existing Mitigation |
|----|--------|--------|------------|---------------------|
| DS-1 | **OPA evaluation timeout from large inputs**: very large attestation or SBOM causes OPA evaluation timeout. | Medium: build/release pipeline stalls. | Low: attestation size is bounded by what Tekton Chains produces and the storage backend limits (etcd ~1 MiB, OCI registry ~4 MiB). | CLI-side evaluation timeout. OPA evaluation performance depends on policy design; no benchmarks have been run against these specific rules. |
| DS-2 | **Policy bundle unavailability**: OCI registry outage blocks all EC validation. | High: all builds/releases blocked. | Low: quay.io has high availability. | Digest-pinned references can be cached by OCI clients. Both `quay.io/enterprise-contract/` and `quay.io/conforma/` namespaces are on the same quay.io host, so they do not provide independent failure-domain redundancy. |

## 5. Deprioritized Threats

| Threat | Rationale |
|--------|-----------|
| **Custom user Rego rules** | Out of scope. Users writing their own Rego can define arbitrary policy. This threat model covers the standard policy repo. |
| **OPA engine vulnerabilities** | OPA is a dependency of the CLI, not the policy repo. Covered by the CLI threat model (EC-2001). |
| **Kubernetes RBAC bypass to modify ECP** | Platform-level threat. The two-namespace architecture and RBAC are Konflux infrastructure concerns, not policy repo concerns. |
| **Network-level MITM on OCI registry** | All OCI fetches use TLS. Digest-pinned references are content-addressed. Covered by the CLI and infrastructure. |
| **Insider attack on policy repo maintainers** | Standard supply chain risk mitigated by GitHub branch protection, CODEOWNERS, and PR review requirements. Not specific to this repo's design. |
| **Malicious custom Regal lint rules** | The `.regal/rules/custom/` directory contains linting rules. These affect CI gating but not policy evaluation at runtime. A compromised lint rule could allow bad Rego to pass review, but the actual threat is the resulting bad Rego (covered by LE-1 through LE-4). |

## 6. Open Questions

1. **Guard rule coverage**: not all policy packages implement the "data found"
   guard-rule pattern. Which packages are missing guard rules, and what input
   shapes would cause them to silently pass?

2. **Rule data schema validation completeness**: not all rule data keys
   consumed via `rule_data.get()` have corresponding JSON schema validation in
   their consuming packages. Which keys lack validation?

3. **Trusted task rules merge precedence**: ruleData-level allow and deny
   rules are concatenated with system-level rules in
   `_trusted_task_rules_data`. Can a ruleData-level allow rule effectively
   override a system-level deny rule for a different pattern? The current code
   evaluates deny before allow, but pattern specificity interactions are not
   well documented.

4. **Collection membership exhaustive check**: is there automated testing that
   every deny rule intended for `@redhat_security` is annotated correctly?
   `checks/annotations.rego` validates annotation format, but a rule missing
   the collection annotation entirely would not be caught.

5. **In-toto referrer trust**: `lib/intoto/trust.rego` discovers in-toto
   statements via `ec.oci.image_referrers`. It first verifies provenance with
   Sigstore, then exposes both the signature-verified associations and a view
   filtered by trusted-task checks. Can an attacker attach additional referrers
   to their image that inject fabricated statements? Does the CLI's attestation
   verification cover referrer-discovered statements, or only
   `input.attestations`?

6. **Data source integrity**: policy bundles can be pinned by digest, but data
   sources (e.g., `oci::quay.io/conforma/policy-data:latest`) are typically
   fetched by tag. See CLI threat model open question 1 for the data source
   integrity discussion.

## 7. Provenance

| Item | Detail |
|------|--------|
| **Author** | Stefano Pentassuglia, with AI assistance |
| **Date** | 2026-08-06 |
| **Sources** | Policy repo source code (commit `5713903f` on `main`): `policy/lib/rule_data/rule_data.rego`, `policy/lib/sigstore/sigstore.rego`, `policy/lib/oci/oci.rego`, `policy/lib/intoto/trust.rego`, `policy/lib/tekton/trusted.rego`, `policy/lib/volatile/volatile_config.rego`, `policy/release/lib/attestations.rego`, `.github/workflows/push-bundles.yaml`, `hack/update-bundles.sh`. CLI threat model (conforma/cli PR #3466, EC-2001). EC-1807 red team investigation context. |
| **Methodology** | 8-section schema from wg-agentic-sdlc. Systematic review of entry points, data flow through `lib/rule_data`, `lib/sigstore`, `lib/tekton/trusted`, `lib/intoto/trust`, and all `policy/release/` packages. |
| **Scope** | conforma/policy repository: Rego rules, rule data, OCI bundle distribution, test infrastructure. Excludes CLI internals (covered by EC-2001), Konflux platform infrastructure, and custom user Rego. |

## 8. Recommended Mitigations

### High priority

1. **Sign policy bundles**: add cosign signing to the `push-bundles.yaml`
   workflow so consumers can cryptographically verify bundle provenance. Without
   this, digest pinning proves content integrity but not origin. (Addresses
   SC-1.)

2. **Universal guard-rule pattern**: adopt a mandatory pattern where every deny
   rule that consumes attestation or rule data has a corresponding "data found"
   prerequisite rule. Packages like `test`, `base_image_registries`, and
   `slsa_provenance_available` follow this pattern. Others do not. The gap
   means missing data produces a silent pass instead of an explicit violation.
   Enforce via a custom Regal lint rule or CI check. (Addresses IE-1, IE-4,
   LE-1.)

3. **Complete rule data schema validation**: make JSON schema validation
   mandatory for every security-critical key consumed via `rule_data.get()`.
   Several packages already do this (e.g., `lib/tekton/trusted.rego` validates
   `trusted_tasks` and `trusted_task_rules`). Keys like `cve_leeway`,
   `allowed_registry_prefixes`, and `allowed_rpm_signature_keys` need the same
   treatment. (Addresses DP-1, DP-4.)

### Medium priority

4. **Collection membership CI check**: add automated testing that asserts every
   deny rule intended for `@redhat_security` has the annotation. A missing
   annotation means the rule silently drops out of enforcement for
   security-focused consumers. (Addresses LE-3.)

5. **Upper bounds on attacker-influenced numerics**: add ceiling validation for
   `cve_leeway` days, `task_expiry_warning_days`, and similar numeric rule data.
   Without upper bounds, an attacker who can influence rule data can set
   arbitrarily large grace periods. (Addresses DP-4.)

6. **Document trusted task rules precedence**: the deny-before-allow evaluation
   order in `is_trusted_task_rules` is correct but not documented outside the
   code. Add explicit documentation on precedence semantics and the interaction
   between system-level and ruleData-level rules. (Addresses LE-4, open
   question 3.)

### Lower priority

7. **Harden in-toto statement discovery**: if referrer-discovered in-toto
   statements are not covered by the CLI's attestation signature verification,
   add explicit trust checks in the Rego layer or document the trust assumption
   that the CLI verifies referrer content. (Addresses open question 5.)

8. **Effective_on annotation inventory**: maintain a tracked list of all rules
   with `effective_on` dates in the future, so time-gated security rules are
   visible to reviewers without grepping annotations. (Addresses LE-2.)

9. **Pin data sources by digest in release ECPs**: operational recommendation
   for Konflux release engineering. Data sources in release-gate ECPs should
   reference OCI bundles by digest, not by mutable tags. (Addresses DP-1. Also
   relevant to CLI threat model SC-2.)
