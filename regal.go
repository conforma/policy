// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"log"
	"os"

	// Register custom rego functions
	_ "github.com/conforma/cli/cmd/validate"
	"github.com/open-policy-agent/regal/cmd"
)

func main() {
	// Remove date and time from any `log.*` calls, as that doesn't add much of value here
	// Evaluate options for logging later
	log.SetFlags(0)

	if err := cmd.RootCommand.Execute(); err != nil {
		code := 1
		if e := (cmd.ExitError{}); errors.As(err, &e) {
			code = e.Code()
		}

		os.Exit(code)
	}
}
