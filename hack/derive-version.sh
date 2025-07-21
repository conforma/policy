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

set -o errexit
set -o nounset
set -o pipefail

# Assumptions:
# 1. A tag exists on branch "main" and contains the major.minor.patch version number
# 2. Git checkouts are done with fetch-depth=0 so we have enough history
# 3. Tags are fetched

# Pass in paths that will be checked for changes since last version.
# Leave blank for "all".
TRACKED_PATHS=$@

# Obtain most recent version tag
LATEST_TAG=$(git describe --tags --abbrev=0 --match="v*.*.*" main)
LATEST_TAG_SHA=$(git rev-parse --verify "$LATEST_TAG"^{commit})

# Check for changes since last version
HAVE_CHANGED=false
DIFF=$(git diff --name-only $LATEST_TAG_SHA -- $TRACKED_PATHS)
[ -z "$DIFF" ] || HAVE_CHANGED=true

# Bump patch version
CURRENT_VERSION_SANITIZED=$(echo "$LATEST_TAG" | grep -Eo '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}')
NEXT_VERSION=$(echo "$CURRENT_VERSION_SANITIZED" | awk -F. -v OFS=. '{$NF++;print}')
NEXT_VERSION=v$NEXT_VERSION

echo ${NEXT_VERSION}
