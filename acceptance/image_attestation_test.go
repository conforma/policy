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
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestImageAttestationFields exercises the real selector and default JSON report.
// The colocated Rego tests retain the full malformed-value and compatibility matrices.
func TestImageAttestationFields(t *testing.T) {
	pinned, err := itsTestFixture.pushTaskBundle("ec2238-images")
	if err != nil {
		t.Fatal(err)
	}
	allowed := strings.Split(pinned, "@")[0] + ":1.0"
	inaccessible := strings.Replace(allowed, "ec2238-images", "ec2238-missing", 1)
	disallowed := strings.Replace(allowed, "localhost:", "127.0.0.1:", 1)
	data := map[string]any{"allowed_step_image_registry_prefixes": []string{itsTestFixture.registryHost + "/"}}
	checks := []struct {
		name, policy, pkg, code string
		collections             []string
		input                   func(any, bool) map[string]any
		good, adverse           any
	}{
		{"G17-registry", "task", "step_image_registries", "step_image_registries.step_images_permitted_v2", []string{"redhat_security"}, taskImageInput, allowed, disallowed},
		{"G17-accessible", "task", "step_images", "step_images.step_images_accessible_v2", nil, taskImageInput, allowed, inaccessible},
		{"G18-registry", "stepaction", "stepaction_image", "stepaction_image.permitted_v2", []string{"redhat_security"}, stepActionImageInput, allowed, disallowed},
		{"G18-accessible", "stepaction", "stepaction_image", "stepaction_image.accessible_v2", nil, stepActionImageInput, allowed, inaccessible},
		{"G19-type", "release", "attestation_type", "attestation_type.known_attestation_type_v2", []string{"minimal", "redhat", "redhat_rpms", "slsa3", "redhat_security"}, attestationTypeInput, "https://in-toto.io/Statement/v0.1", "unknown-type"},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			selectors := []string{check.code, check.pkg}
			for _, collection := range check.collections {
				selectors = append(selectors, "@"+collection)
			}
			for _, selector := range selectors {
				t.Run(selector, func(t *testing.T) {
					type fieldCase struct {
						name              string
						value             any
						present, rejected bool
					}
					cases := []fieldCase{
						{"valid", check.good, true, false},
						{"missing", nil, false, true},
					}
					if selector == check.code || selector == check.pkg {
						cases = append(cases,
							fieldCase{"null", nil, true, true},
							fieldCase{"object", map[string]any{}, true, true},
							fieldCase{"adverse", check.adverse, true, true},
						)
					}
					for _, tc := range cases {
						t.Run(tc.name, func(t *testing.T) {
							r := imageAttestationReport(t, check.policy, selector, check.input(tc.value, tc.present), data, "2027-01-11T00:00:01Z")
							assertImageAttestationCode(t, r, check.code, tc.rejected, false)
						})
					}
				})
			}
			// The CLI makes a failure effective strictly after its timestamp.
			for _, when := range []string{"2027-01-10T00:00:00Z", "2027-01-11T00:00:00Z"} {
				t.Run("migration-warning/"+when, func(t *testing.T) {
					r := imageAttestationReport(t, check.policy, check.code, check.input(nil, false), data, when)
					assertImageAttestationCode(t, r, check.code, false, true)
				})
			}
			t.Run("legacy-adverse-control", func(t *testing.T) {
				legacy := strings.TrimSuffix(check.code, "_v2")
				r := imageAttestationReport(t, check.policy, legacy, check.input(check.adverse, true), data, "2027-01-11T00:00:01Z")
				assertImageAttestationCode(t, r, legacy, true, false)
			})
		})
	}
	// The actual SLSA v1 selector must also retain allowed statement types.
	v1 := attestationTypeInput("https://in-toto.io/Statement/v1", true)
	statement := v1["attestations"].([]any)[0].(map[string]any)["statement"].(map[string]any)
	statement["predicateType"] = slsaProvenanceV1
	statement["predicate"] = map[string]any{"buildDefinition": map[string]any{"buildType": tektonBuildType}}
	r := imageAttestationReport(t, "release", "attestation_type", v1, data, "2027-01-11T00:00:01Z")
	assertImageAttestationCode(t, r, "attestation_type.known_attestation_type_v2", false, false)
	r = imageAttestationReport(t, "release", "attestation_type", map[string]any{"attestations": []any{}}, data, "2027-01-11T00:00:01Z")
	assertImageAttestationCode(t, r, "attestation_type.pipelinerun_attestation_found", true, false)
}

func TestImageAttestationDigestWarnings(t *testing.T) {
	pinned, err := itsTestFixture.pushTaskBundle("ec2238-pinning")
	if err != nil {
		t.Fatal(err)
	}
	tag := strings.Split(pinned, "@")[0] + ":1.0"
	digest := strings.Split(pinned, "@")[1]
	data := map[string]any{
		"trusted_task_rules_enabled": true,
		"trusted_task_rules": map[string]any{
			"allow": map[string]any{"test": []any{map[string]any{"pattern": "oci://" + strings.Split(pinned, "@")[0] + "*"}}},
			"deny":  map[string]any{},
		},
	}
	checks := []struct {
		name, policy, pkg, code string
		collections             []string
		input                   func(string) map[string]any
	}{
		{"RA03-BUNDLE-DIGEST-SHAPE-001", "pipeline", "task_bundle", "task_bundle.unpinned_task_bundle", []string{"redhat_security"}, pipelineBundleInput},
		{"RA29-DIGEST-SHAPE-001", "release", "trusted_task", "trusted_task.pinned", []string{"redhat", "redhat_rpms", "redhat_security"}, trustedTaskBundleInput},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			selectors := []string{check.code, check.pkg}
			for _, collection := range check.collections {
				selectors = append(selectors, "@"+collection)
			}
			for _, selector := range selectors {
				t.Run(selector, func(t *testing.T) {
					for _, tc := range []struct {
						name, ref string
						warning   bool
					}{
						{"tag-only", tag, true},
						{"arbitrary-suffix", tag + "@not-a-digest", true},
						{"empty-hash", tag + "@sha256:", true},
						{"valid-digest", tag + "@" + digest, false},
					} {
						t.Run(tc.name, func(t *testing.T) {
							r := imageAttestationReport(t, check.policy, selector, check.input(tc.ref), data, "2027-01-11T00:00:01Z")
							assertImageAttestationCode(t, r, check.code, false, tc.warning)
						})
					}
				})
			}
		})
	}
}

func taskImageInput(value any, present bool) map[string]any {
	step := map[string]any{"name": "step"}
	if present {
		step["image"] = value
	}
	return map[string]any{"apiVersion": "tekton.dev/v1", "kind": "Task", "metadata": map[string]any{"name": "task"}, "spec": map[string]any{"steps": []any{step}}}
}

func stepActionImageInput(value any, present bool) map[string]any {
	spec := map[string]any{}
	if present {
		spec["image"] = value
	}
	return map[string]any{"apiVersion": "tekton.dev/v1beta1", "kind": "StepAction", "metadata": map[string]any{"name": "action"}, "spec": spec}
}

func attestationTypeInput(value any, present bool) map[string]any {
	statement := map[string]any{"predicateType": "https://slsa.dev/provenance/v0.2", "predicate": map[string]any{"buildType": "tekton.dev/v1beta1/PipelineRun"}}
	if present {
		statement["_type"] = value
	}
	return map[string]any{"attestations": []any{map[string]any{"statement": statement}}}
}

func pipelineBundleInput(ref string) map[string]any {
	task := map[string]any{"name": "task", "taskRef": map[string]any{"resolver": "bundles", "params": []any{
		map[string]any{"name": "bundle", "value": ref}, map[string]any{"name": "name", "value": "task"},
	}}}
	return map[string]any{"apiVersion": "tekton.dev/v1", "kind": "Pipeline", "spec": map[string]any{"tasks": []any{task}}}
}

func trustedTaskBundleInput(ref string) map[string]any {
	doc := attestationTypeInput("https://in-toto.io/Statement/v0.1", true)
	statement := doc["attestations"].([]any)[0].(map[string]any)["statement"].(map[string]any)
	predicate := statement["predicate"].(map[string]any)
	task := pipelineBundleInput(ref)["spec"].(map[string]any)["tasks"].([]any)[0].(map[string]any)
	predicate["buildConfig"] = map[string]any{"tasks": []any{map[string]any{"name": "task", "ref": task["taskRef"]}}}
	return doc
}

func imageAttestationReport(t *testing.T, policy, selector string, doc, ruleData map[string]any, effectiveTime string) report {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, value any) string {
		t.Helper()
		content, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		filename := filepath.Join(dir, name)
		if err := os.WriteFile(filename, content, 0o600); err != nil {
			t.Fatal(err)
		}
		return filename
	}
	inputFile := write("input.json", doc)
	configFile := write("policy.json", map[string]any{"sources": []any{map[string]any{
		"policy":   []string{filepath.Join(root, "policy/lib"), filepath.Join(root, "policy", policy)},
		"data":     []string{filepath.Join(root, "example/data")},
		"ruleData": ruleData,
		"config":   map[string]any{"include": []string{selector}},
	}}})
	cmd := exec.Command(ecBinary, "validate", "input", "--file", inputFile, "--policy", configFile,
		"--strict=false", "--info", "--output", "json", "--effective-time", effectiveTime, "--allow-past-effective-time")
	output, err := cmd.Output()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			t.Fatalf("validate input: %v\n%s", err, exit.Stderr)
		}
		t.Fatal(err)
	}
	var r report
	if err := json.Unmarshal(output, &r); err != nil {
		t.Fatalf("decode report: %v\n%s", err, output)
	}
	if len(r.FilePaths) != 1 {
		t.Fatalf("expected one evaluated input, got %d", len(r.FilePaths))
	}
	return r
}

func assertImageAttestationCode(t *testing.T, r report, code string, violation, warning bool) {
	t.Helper()
	for _, input := range r.FilePaths {
		hasCode := func(result result) bool { return result.Metadata.Code == code }
		if got := slices.ContainsFunc(input.Violations, hasCode); got != violation {
			t.Errorf("violation %s: got %v, want %v; report: %+v", code, got, violation, r)
		}
		if got := slices.ContainsFunc(input.Warnings, hasCode); got != warning {
			t.Errorf("warning %s: got %v, want %v; report: %+v", code, got, warning, r)
		}
	}
}
