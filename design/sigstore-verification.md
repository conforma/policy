# Sigstore Verification in Rego Rules

ec-policies uses `ec.sigstore.verify_image` and `ec.sigstore.verify_attestation`
built-ins (provided by ec-cli) to verify image signatures and attestations.

## What does the built-in return?

`ec.sigstore.verify_image` returns an object with three fields:

- `success` (bool) — true when verification succeeds (no errors)
- `errors` ([]string) — verification error messages, empty on success
- `signatures` ([]signature) — matching signatures

`ec.sigstore.verify_attestation` returns a similar object with `attestations`
instead of `signatures`. These types are declared in ec-cli at
`internal/rego/sigstore/sigstore.go` using OPA's `types.NewObject` — they are
not visible from the ec-policies repo.

## Where does attestation verification stop and policy trust begin?

`ec.sigstore.verify_attestation` verifies the Sigstore signature, applies
Cosign's in-toto subject claim verifier to the requested OCI reference, and
returns the parsed attestations. It does not evaluate policy rule data such as
`trusted_task_rules`; that belongs to the Rego layer.

Policy code must gate on `success` before inspecting an attestation's contents.
When a policy needs to explain task-trust failures, retain a view of the
successfully verified attestations before applying task trust, then derive the
fully trusted view from it. Failed verification results must not enter task
evaluation merely to improve diagnostics.

## Why can't I use count() or direct field access on the result?

The built-in declares `errors` as `types.NewArray([]types.Type{types.S}, nil)` —
a *static* array type in OPA's type system. OPA's strict type checker cannot
unify this with `count()`'s expected input type, and direct field comparison
(`info.success == true`) triggers a panic in the type checker's `unifies`
function. These are OPA bugs/limitations, not policy errors.

Use `object.get()` to bypass the strict typing — it returns an untyped value:

```rego
# Works — object.get returns untyped
object.get(info, "success", false) == true

# Panics — direct field access on typed built-in return
info.success == true

# Type error — count() rejects the static array type
count(info.errors) == 0
```

Iterating with `some _ in info.errors` works because `some ... in` handles the
typed array correctly. This is why `source_image.rego` can iterate errors
directly but you can't count them.

## How should verification options be constructed?

`policy/lib/sigstore/sigstore.rego` defines a shared `opts` object that reads
from `data.config.default_sigstore_opts` at runtime, falling back to safe
defaults (empty strings, `ignore_rekor: false`). This is the single source of
truth for deployment-wide sigstore configuration — it carries `rekor_url`,
`ignore_rekor`, certificate identity fields, and a default `public_key`.

Each signing identity in rule data contains the complete set of options needed
for its verification method. Look up a named entry from the `signing_identities`
rule data and pass it directly:

```rego
# _signing_identity is an object looked up from rule_data signing_identities
# by name (e.g., "rh-release"). Its fields match sigstore.opts field names.
info := ec.sigstore.verify_image(image_ref, _signing_identity)
```

There are no useful shared defaults — every verification method requires a
distinct combination of fields (public key vs keyless, Rekor strategy), so
each signing identity is self-contained.

## What patterns exist for checking verification results?

| File | Pattern | Use case |
|------|---------|----------|
| `source_image.rego` | `some raw_error in info.errors` | Surface each error as a separate deny message |
| `lib/intoto/trust.rego` | `object.get(verification, "success", false) == true` | Boolean pass/fail gate |
| `base_image_registries.rego` | `object.get(info, "success", false) == true` | Boolean pass/fail gate |
| `lib/oci/oci.rego` | `object.get(info, "errors", [])` per referrer, filtered by `errors == []` | Gate a set of OCI referrers/tag refs to the signature-verified subset (fail-closed) |
| `lib/sbom/sbom.rego` | `some raw_error in result.errors` over the failures set | Surface why each discovered SBOM was excluded, as warnings |

Prefer `object.get(info, "success", false) == true` for pass/fail checks.
Use `some raw_error in info.errors` when you need to surface individual error
messages to the user.
