#!/usr/bin/env bash
# Copyright The Conforma Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Guardrail check for acceptance-only Rego files.
#
# In Rego, rules declared in the same package are unioned across all loaded
# files. An acceptance-only shim that declares a production package name (e.g.
# `package lib.sbom` or `package release.foo`) and is colocated on the
# production `ec eval` load path would silently extend production behavior.
#
# Production `ec eval` invocations for this repository load ./policy (see the
# POLICY_DIR / TEST_FILES variables in the Makefile) and do not include
# acceptance/policy/**. Any new acceptance rego file that redeclares a
# production package name must carry an explicit
# `# ACCEPTANCE-ONLY: <justification>` marker comment documenting why it does
# not leak to production. This script enforces that convention.
#
# See AGENTS.md ("Acceptance shims must not extend production packages") for
# the human-readable rule this check backs.
#
# Usage:
#   hack/lint-acceptance.sh                       # scan acceptance/
#   hack/lint-acceptance.sh path/to/acceptance    # scan a specific tree
#
# Exits non-zero and prints each offending file if any acceptance rego
# declares `package lib.*` or `package release.*` without the marker comment.

set -o errexit
set -o pipefail
set -o nounset

if [ "${RUNNER_DEBUG:-}" == "1" ]; then
  set -x
fi

ROOT="${1:-acceptance}"

if [ ! -d "${ROOT}" ]; then
  echo "lint-acceptance: directory not found: ${ROOT}" >&2
  exit 2
fi

# Match a real (not commented-out) package declaration for `lib.*` or
# `release.*`. Leading whitespace is tolerated; a `#` before `package` is not.
# The trailing anchor requires the package path to end or continue with a `.`,
# which prevents matching a hypothetical `package library` or `package releases`.
PACKAGE_RE='^[[:space:]]*package[[:space:]]+(lib|release)(\.|[[:space:]]*$)'
MARKER_RE='#[[:space:]]*ACCEPTANCE-ONLY:'

offenders=()

while IFS= read -r -d '' file; do
  if grep -Eq "${PACKAGE_RE}" "${file}"; then
    if ! grep -Eq "${MARKER_RE}" "${file}"; then
      offenders+=("${file}")
    fi
  fi
done < <(find "${ROOT}" -type f -name '*.rego' -print0)

if [ "${#offenders[@]}" -gt 0 ]; then
  echo "lint-acceptance: acceptance rego files declare a production package" >&2
  echo "                (lib.* or release.*) without the required marker" >&2
  echo "                '# ACCEPTANCE-ONLY: <justification>':" >&2
  for f in "${offenders[@]}"; do
    echo "  - ${f}" >&2
  done
  echo >&2
  echo "See AGENTS.md, 'Acceptance shims must not extend production" >&2
  echo "packages', for the guardrail." >&2
  exit 1
fi
