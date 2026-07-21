---
paths:
  - "policy/**/*.rego"
---

# Policy Rule Conventions

- Every `.rego` file must have a corresponding `_test.rego` — 100% coverage enforced
- All rules require METADATA annotations (title, description, short_name, failure_msg)
- Release policy rules declare collection membership via `collections:` in their METADATA annotations
- Run `make fmt` before committing; `make generate-docs` after changing rule metadata (titles, descriptions, collections, or adding new rules)
