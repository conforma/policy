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

# Updates a local clone of redhat-appstudio/infra-deployments to use the latest
# packages produced by this repository.
# Usage:
#   update-infra-deployments.sh <PATH_TO_INFRA_DEPLOYMENTS>

set -o errexit
set -o pipefail
set -o nounset

TARGET_DIR="${1}"
cd "${TARGET_DIR}" || exit 1

TASK_POLICY_REF='quay.io/conforma/task-policy:latest'

function oci_source() {
  img="${1}"
  manifest="$(mktemp --tmpdir)"
  function cleanup() {
    # shellcheck disable=SC2317
    rm "${manifest}"
  }
  trap cleanup RETURN
  # Must use --raw because skopeo cannot handle an OPA bundle image format.
  skopeo inspect --raw  "docker://${img}" > "${manifest}"
  revision="$(jq -r '.annotations["org.opencontainers.image.revision"]' "${manifest}")"
  if [[ -n "${revision}" && "${revision}" != "null" ]]; then
    img="${img/:latest/:git-${revision}}"
  fi
  digest="$(sha256sum "${manifest}" | awk '{print $1}')"
  img_ref_tag="${img}"
  img_ref_digest="${img/:*/}@sha256:${digest}"
  # sanity check
  diff <(skopeo inspect --raw "docker://${img_ref_tag}") <(skopeo inspect --raw "docker://${img_ref_digest}") >&2
  img_ref="${img}@sha256:${digest}"
  echo "oci::${img_ref}"
}

function update_ecp_resources() {
  local source_matcher=$1
  local source_url=$2

  for yaml_file in $(find . -type f \( -name "*.yaml" -o -name "*.yml" \)); do
      # First, filter out irrelevant files. stderr is discarded because if the YAML file is not a
      # match, then yq prints the error "no matches found" which is quite noisy given the amount of
      # YAML files being ignored.
      yq e -e \
          '(select(has("kind")) | select(.kind == "EnterpriseContractPolicy"))' \
          $yaml_file 2> /dev/null || continue
      # Finally, update the source references. A previous iteration used yq to perform a more
      # precise update. However, making a conditional update is non-trivial. sed is simpler here.
      sed -i 's%'${source_matcher}'%'${source_url}'%' $yaml_file
    done
}

echo 'Resolving task bundle image references...'
TASK_POLICY_REF_OCI="$(oci_source ${TASK_POLICY_REF})"
echo "Resolved task policy is ${TASK_POLICY_REF_OCI}"

echo 'Updating infra-deployments...'
# The "oci::" is not required by EC CLI. The expression below handles both cases. It's important to
# note that this script will normalize the source references to always include the oci:: prefix.
update_ecp_resources '\b\(oci::\)\{0,1\}.*/\(ec-\)\{0,1\}task-policy:.*$' "${TASK_POLICY_REF_OCI}"
echo 'infra-deployments updated successfully'
