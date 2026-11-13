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

# Verify that every go.mod in the repo declares the same go directive as the
# root go.mod. Drift can happen when Renovate bumps a dependency whose own go
# directive floor rises, silently relying on GOTOOLCHAIN=auto to download the
# right version at build time.

set -o errexit
set -o nounset
set -o pipefail

root_go_mod="go.mod"
root_directive=$(awk '/^go /{print $2; exit}' "${root_go_mod}")

if [[ -z "${root_directive}" ]]; then
  echo "ERROR: no go directive found in ${root_go_mod}" >&2
  exit 1
fi

rc=0

for f in $(git ls-files '*/go.mod'); do
  sub_directive=$(awk '/^go /{print $2; exit}' "${f}")
  if [[ -z "${sub_directive}" ]]; then
    echo "ERROR: no go directive found in ${f}" >&2
    rc=1
  elif [[ "${sub_directive}" != "${root_directive}" ]]; then
    echo "ERROR: go directive drift: ${f} has go ${sub_directive}, root go.mod has go ${root_directive}" >&2
    rc=1
  fi
done

if [[ "${rc}" -eq 0 ]]; then
  echo "OK: all go.mod files declare go ${root_directive}"
fi

exit "${rc}"
