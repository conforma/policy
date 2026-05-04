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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	// Neded so the "go run" command can execute.
	_ "github.com/conforma/cli/cmd"
)

const (
	policyInputFilename  = "input.json"
	policyConfigFilename = "policy.json"
)

var ecBinary string

func TestMain(m *testing.M) {
	tmpBin, err := os.CreateTemp("", "ec-test-*")
	if err != nil {
		log.Fatalf("creating temp file for ec binary: %v", err)
	}
	tmpBin.Close()
	ecBinary = tmpBin.Name()

	log.Printf("building ec binary at %s...", ecBinary)
	start := time.Now()
	cmd := exec.Command("go", "build", "-o", ecBinary, "github.com/conforma/cli")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Remove(ecBinary)
		log.Fatalf("building ec binary: %v", err)
	}
	log.Printf("ec binary built in %s", time.Since(start))

	code := m.Run()
	os.Remove(ecBinary)
	os.Exit(code)
}

var (
	//go:embed samples/policy-input-golden-container.json
	sampleGCPolicyInput string
	//go:embed samples/clamav-task.json
	sampleClamAVTask string
	//go:embed samples/trusted-task.json
	sampleTrustedTask string
	//go:embed samples/untrusted-task.json
	sampleUntrustedTask string
	//go:embed samples/untrusted-task-despite-valid-oci-ref-tag.json
	sampleUntrustedTaskDespiteValidOciRefTag string
	//go:embed samples/policy-input-spdx-sbom.json
	sampleSPDXSBOM string
	//go:embed samples/policy-input-cdx-sbom.json
	sampleCDXSBOM string
)

type testStateKey struct{}

type testState struct {
	id                   string
	tempDir              string
	variables            map[string]string
	report               report
	cliPath              string
	inputFileName        string
	configFileName       string
	acceptanceModulePath string
	effectiveTime        string
}

// Types used for parsing violations and warnings from report
type (
	metadata struct {
		Code        string   `json:"code"`
		Description string   `json:"description"`
		Title       string   `json:"title"`
		Solution    string   `json:"solution"`
		Term        string   `json:"term"`
		Collections []string `json:"collections"`
	}
	result struct {
		Message  string   `json:"msg"`
		Metadata metadata `json:"metadata,omitempty"`
	}

	input struct {
		Violations []result `json:"violations"`
		Warnings   []result `json:"warnings"`
	}

	report struct {
		FilePaths []input `json:"filepaths"`
	}
)

func writeSampleGCPolicyInput(ctx context.Context, sampleName string) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("writeSampleGCPolicyInput get test state: %w", err)
	}

	f, err := os.Create(ts.inputFileName)
	if err != nil {
		return ctx, fmt.Errorf("creating %s file: %w", ts.inputFileName, err)
	}
	defer f.Close()

	var content string
	switch sampleName {
	case "golden-container":
		content = sampleGCPolicyInput
	case "clamav-task":
		content = sampleClamAVTask
	case "trusted-task":
		content = sampleTrustedTask
	case "untrusted-task":
		content = sampleUntrustedTask
	case "untrusted-task-despite-valid-oci-ref-tag":
		content = sampleUntrustedTaskDespiteValidOciRefTag
	case "spdx-sbom":
		content = sampleSPDXSBOM
	case "cdx-sbom":
		content = sampleCDXSBOM
	default:
		return ctx, fmt.Errorf("%q is not a known sample name", sampleName)
	}

	if _, err := f.WriteString(content); err != nil {
		return ctx, fmt.Errorf("writing %s file: %w", ts.inputFileName, err)
	}

	return ctx, nil
}

func writePolicyConfig(ctx context.Context, config *godog.DocString) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("writePolicyConfig get test state: %w", err)
	}

	f, err := os.Create(ts.configFileName)
	if err != nil {
		return ctx, fmt.Errorf("creating %s file: %w", ts.configFileName, err)
	}
	defer f.Close()

	content := replaceVariables(config.Content, ts.variables)

	if _, err := f.WriteString(content); err != nil {
		return ctx, fmt.Errorf("writing %s file: %w", ts.configFileName, err)
	}

	return ctx, nil
}

func setEffectiveTime(ctx context.Context, effectiveTime string) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("setEffectiveTime get test state: %w", err)
	}

	ts.effectiveTime = effectiveTime

	return setTestState(ctx, ts), nil
}

func validateInputWithPolicyConfig(ctx context.Context) (context.Context, error) {
	ts, err := getTestState(ctx)
	if err != nil {
		return ctx, fmt.Errorf("validateInputWithPolicyConfig get test state: %w", err)
	}

	args := []string{
		"validate",
		"input",
		"--file",
		ts.inputFileName,
		"--policy",
		ts.configFileName,
		"--strict=false",
		"--info",
		"--output",
		"json",
	}
	if ts.effectiveTime != "" {
		args = append(args, "--effective-time", ts.effectiveTime)
	}

	cmd := exec.Command(ecBinary, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[%s] running ec validate input...", ts.id)
	start := time.Now()
	if err := cmd.Run(); err != nil {
		return ctx, fmt.Errorf("running ec validate input: %w\n%s", err, stderr.String())
	}
	log.Printf("[%s] ec validate input completed in %s", ts.id, time.Since(start))

	var r report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		return ctx, fmt.Errorf("unmarshalling report: %w", err)
	}
	ts.report = r

	return setTestState(ctx, ts), nil
}

func thereShouldBeNoViolationsInTheResult(ctx context.Context) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		if len(filepath.Violations) != 0 {
			return errors.New(prettifyResults("expected no violations, got:", filepath.Violations))
		}
	}

	return nil
}

func thereShouldBeViolationsInTheResult(ctx context.Context) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	violationCount := 0
	for _, filepath := range ts.report.FilePaths {
		violationCount += len(filepath.Violations)
	}

	if violationCount == 0 {
		return errors.New("expected violations, but got none")
	}

	return nil
}

func thereShouldBeNoWarningsInTheResult(ctx context.Context) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		if len(filepath.Warnings) != 0 {
			return errors.New(prettifyResults("expected no warnings, got:", filepath.Warnings))
		}
	}

	return nil
}

func thereShouldBeNoViolationsWithCollectionInTheResult(ctx context.Context, collection string) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		for _, violation := range filepath.Violations {
			if slices.Contains(violation.Metadata.Collections, collection) {
				return errors.New(prettifyResults(fmt.Sprintf("expected no violations with collection %q, got:", collection), filepath.Violations))
			}
		}
	}

	return nil
}

func thereShouldBeNoViolationsWithPackageInTheResult(ctx context.Context, pkg string) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		for _, violation := range filepath.Violations {
			if strings.HasPrefix(violation.Metadata.Code, pkg) {
				return errors.New(prettifyResults(fmt.Sprintf("expected no violations with package %q, got:", pkg), filepath.Violations))
			}
		}
	}

	return nil
}

func thereShouldBeNoViolationsWithRuleAndTermInTheResult(ctx context.Context, code string, term string) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		for _, violation := range filepath.Violations {
			if violation.Metadata.Code == code && violation.Metadata.Term == term {
				return errors.New(prettifyResults(fmt.Sprintf("expected no violations with code %q and term %q, got:", code, term), filepath.Violations))
			}
		}
	}

	return nil
}

func thereShouldBeNoWarningsWithPackageInTheResult(ctx context.Context, pkg string) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		for _, warning := range filepath.Warnings {
			if strings.HasPrefix(warning.Metadata.Code, pkg) {
				return errors.New(prettifyResults(fmt.Sprintf("expected no violations with package %q, got:", pkg), filepath.Violations))
			}
		}
	}

	return nil
}

func thereShouldBeViolationsWithCodeInTheResult(ctx context.Context, code string) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		for _, violation := range filepath.Violations {
			if violation.Metadata.Code == code {
				return nil
			}
		}
	}

	return fmt.Errorf("expected at least one violation with code %q, but found none", code)
}

func thereShouldBeNoViolationsWithCodeInTheResult(ctx context.Context, code string) error {
	ts, err := getTestState(ctx)
	if err != nil {
		return fmt.Errorf("reading test state: %w", err)
	}

	for _, filepath := range ts.report.FilePaths {
		for _, violation := range filepath.Violations {
			if violation.Metadata.Code == code {
				return errors.New(prettifyResults(fmt.Sprintf("expected no violations with code %q, got:", code), filepath.Violations))
			}
		}
	}

	return nil
}

func prettifyResults(msg string, results []result) string {
	for _, violation := range results {
		code := violation.Metadata.Code
		msg += fmt.Sprintf("\n\t%s:\t%s", code, violation.Message)
	}
	return msg
}

func replaceVariables(content string, variables map[string]string) string {
	for name, value := range variables {
		re := regexp.MustCompile(`\$` + name + `\b`)
		content = re.ReplaceAllString(content, value)
	}
	return content
}

func setupScenario(ctx context.Context, sc *godog.Scenario) (context.Context, error) {
	tempDir, err := os.MkdirTemp("", "policy-")
	if err != nil {
		return ctx, fmt.Errorf("setting up scenario: %w", err)
	}

	acceptanceModulePath, err := filepath.Abs(".")
	if err != nil {
		return ctx, fmt.Errorf("getting acceptance module path: %w", err)
	}

	gitroot, err := filepath.Abs("..")
	if err != nil {
		return ctx, fmt.Errorf("getting gitroot: %w", err)
	}

	ts := testState{
		id:                   sc.Id,
		cliPath:              filepath.Join(gitroot, "acceptance/bin/ec"),
		tempDir:              tempDir,
		acceptanceModulePath: acceptanceModulePath,
		inputFileName:        path.Join(tempDir, policyInputFilename),
		configFileName:       path.Join(tempDir, policyConfigFilename),
		variables: map[string]string{
			"GITROOT": gitroot,
		},
	}

	return setTestState(ctx, ts), nil
}

func tearDownScenario(ctx context.Context, sc *godog.Scenario, _ error) (context.Context, error) {
	// Purposely ignore errors here to prevent a tear down error to mask a test error.
	ts, _ := getTestState(ctx)

	if ts.tempDir != "" {
		_ = os.RemoveAll(ts.tempDir)
	}
	return ctx, nil
}

func getTestState(ctx context.Context) (testState, error) {
	ts, ok := ctx.Value(testStateKey{}).(testState)
	if !ok {
		return testState{}, errors.New("test state not set")
	}
	return ts, nil
}

func setTestState(ctx context.Context, ts testState) context.Context {
	return context.WithValue(ctx, testStateKey{}, ts)
}

func InitializeScenario(sc *godog.ScenarioContext) {
	sc.Before(setupScenario)

	sc.Step(`^a sample policy input "([^"]*)"$`, writeSampleGCPolicyInput)
	sc.Step(`^a policy config:$`, writePolicyConfig)
	sc.Step(`^an effective time of "([^"]*)"$`, setEffectiveTime)
	sc.Step(`^input is validated$`, validateInputWithPolicyConfig)
	sc.Step(`^there should be no violations in the result$`, thereShouldBeNoViolationsInTheResult)
	sc.Step(`^there should be violations in the result$`, thereShouldBeViolationsInTheResult)
	sc.Step(`^there should be no warnings in the result$`, thereShouldBeNoWarningsInTheResult)
	sc.Step(`^there should be no violations with "([^"]*)" collection in the result$`, thereShouldBeNoViolationsWithCollectionInTheResult)
	sc.Step(`^there should be no violations with "([^"]*)" package in the result$`, thereShouldBeNoViolationsWithPackageInTheResult)
	sc.Step(`^there should be no violations with "([^"]*)" code and "([^"]*)" term in the result$`, thereShouldBeNoViolationsWithRuleAndTermInTheResult)
	sc.Step(`^there should be no warnings with "([^"]*)" package in the result$`, thereShouldBeNoWarningsWithPackageInTheResult)
	sc.Step(`^there should be violations with "([^"]*)" code in the result$`, thereShouldBeViolationsWithCodeInTheResult)
	sc.Step(`^there should be no violations with "([^"]*)" code in the result$`, thereShouldBeNoViolationsWithCodeInTheResult)

	sc.After(tearDownScenario)
}

func TestFeatures(t *testing.T) {
	suite := godog.TestSuite{
		ScenarioInitializer: InitializeScenario,
		Options: &godog.Options{
			Format:   "pretty",
			Paths:    []string{"features"},
			TestingT: t, // Testing instance that will run subtests.
			Strict:   true,
		},
	}

	if suite.Run() != 0 {
		t.Fatal("non-zero status returned, failed to run feature tests")
	}
}
