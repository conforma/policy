#!/bin/bash
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

# This script is a wrapper around the EC version of OPA. Due to the custom rego functions provided
# by EC, e.g. ec.oci.image_files, a custom version of OPA is required.
set -euo pipefail
cd "$(dirname "$0")/.."
make --silent bin/ec
exec bin/ec opa "$@"
