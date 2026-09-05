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
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	ggcrmutate "github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

const (
	testResultArtifactType = "application/vnd.in-toto+json"
	testResultPredicate    = "https://in-toto.io/attestation/test-result/v0.1"
)

type itsFixture struct {
	server             *httptest.Server
	inputs             map[string]string
	publicKeyJSON      string
	registryHost       string
	signer             *cosign.KeysBytes
	rekorSigner        signature.Signer
	rekorPublicKeyFile string
	tempDir            string
}

type itsTestRun struct {
	testName            string
	timestamp           string
	tasks               []map[string]any
	includeProvenance   bool
	malformedProvenance bool
}

func newITSFixture() (*itsFixture, error) {
	server := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	u, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		return nil, fmt.Errorf("parse registry URL: %w", err)
	}

	keys, err := cosign.GenerateKeyPair(func(bool) ([]byte, error) { return []byte{}, nil })
	if err != nil {
		server.Close()
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	publicKeyJSON, err := json.Marshal(string(keys.PublicBytes))
	if err != nil {
		server.Close()
		return nil, fmt.Errorf("encode public key: %w", err)
	}

	rekorSigner, _, err := signature.NewECDSASignerVerifier(elliptic.P256(), rand.Reader, crypto.SHA256)
	if err != nil {
		server.Close()
		return nil, fmt.Errorf("generate Rekor signing key: %w", err)
	}
	rekorPublicKey, err := cryptoutils.MarshalPublicKeyToPEM(rekorSigner.Public())
	if err != nil {
		server.Close()
		return nil, fmt.Errorf("encode Rekor public key: %w", err)
	}
	tempDir, err := os.MkdirTemp("", "its-acceptance-")
	if err != nil {
		server.Close()
		return nil, fmt.Errorf("create ITS fixture directory: %w", err)
	}
	rekorPublicKeyFile := filepath.Join(tempDir, "rekor.pub")
	if err := os.WriteFile(rekorPublicKeyFile, rekorPublicKey, 0o600); err != nil {
		server.Close()
		_ = os.RemoveAll(tempDir)
		return nil, fmt.Errorf("write Rekor public key: %w", err)
	}

	f := &itsFixture{
		server:             server,
		inputs:             map[string]string{},
		publicKeyJSON:      string(publicKeyJSON),
		registryHost:       "localhost:" + u.Port(),
		signer:             keys,
		rekorSigner:        rekorSigner,
		rekorPublicKeyFile: rekorPublicKeyFile,
		tempDir:            tempDir,
	}

	trustedBundle, err := f.pushTaskBundle("trusted-tasks")
	if err != nil {
		f.close()
		return nil, err
	}
	deniedBundle, err := f.pushTaskBundle("denied-tasks")
	if err != nil {
		f.close()
		return nil, err
	}

	cases := map[string][]itsTestRun{
		"its-fully-trusted": {{
			testName:          "clair-integration",
			timestamp:         "2026-01-01T00:00:00Z",
			tasks:             []map[string]any{slsaV1Task("clair-scan", trustedBundle)},
			includeProvenance: true,
		}},
		"its-untrusted-helper": {{
			testName:  "clair-integration",
			timestamp: "2026-01-01T00:00:00Z",
			tasks: []map[string]any{
				slsaV1Task("clair-scan", trustedBundle),
				slsaV1Task("prepare-test", deniedBundle),
			},
			includeProvenance: true,
		}},
		"its-unknown-helper": {{
			testName:  "clair-integration",
			timestamp: "2026-01-01T00:00:00Z",
			tasks: []map[string]any{
				slsaV1Task("clair-scan", trustedBundle),
				slsaV1Task("unknown-helper", ""),
			},
			includeProvenance: true,
		}},
		"its-missing-provenance": {{
			testName:  "clair-integration",
			timestamp: "2026-01-01T00:00:00Z",
		}},
		"its-malformed-provenance": {{
			testName:            "clair-integration",
			timestamp:           "2026-01-01T00:00:00Z",
			includeProvenance:   true,
			malformedProvenance: true,
		}},
		"its-latest-retry-trusted": {
			{testName: "integration-1", timestamp: "2026-01-01T01:00:00Z", tasks: []map[string]any{slsaV1Task("test-1", trustedBundle)}, includeProvenance: true},
			{testName: "integration-2", timestamp: "2026-01-01T01:00:00Z", tasks: []map[string]any{slsaV1Task("test-2", trustedBundle)}, includeProvenance: true},
			{testName: "integration-3", timestamp: "2026-01-01T01:00:00Z", tasks: []map[string]any{slsaV1Task("test-3", trustedBundle)}, includeProvenance: true},
			{testName: "integration-4", timestamp: "2026-01-01T01:00:00Z", tasks: []map[string]any{slsaV1Task("test-4", trustedBundle)}, includeProvenance: true},
			{testName: "integration-5", timestamp: "2026-01-01T01:00:00Z", tasks: []map[string]any{slsaV1Task("clair-scan", deniedBundle)}, includeProvenance: true},
			{testName: "integration-5", timestamp: "2026-01-01T02:00:00Z", tasks: []map[string]any{slsaV1Task("clair-scan", deniedBundle)}, includeProvenance: true},
			{testName: "integration-5", timestamp: "2026-01-01T03:00:00Z", tasks: []map[string]any{slsaV1Task("clair-scan", trustedBundle)}, includeProvenance: true},
		},
		"its-latest-retry-untrusted": {
			{testName: "clair-integration", timestamp: "2026-01-01T01:00:00Z", tasks: []map[string]any{slsaV1Task("clair-scan", trustedBundle)}, includeProvenance: true},
			{testName: "clair-integration", timestamp: "2026-01-01T02:00:00Z", tasks: []map[string]any{slsaV1Task("clair-scan", deniedBundle)}, includeProvenance: true},
		},
	}

	for caseName, runs := range cases {
		input, err := f.publishCase(caseName, runs)
		if err != nil {
			f.close()
			return nil, fmt.Errorf("publish %s fixture: %w", caseName, err)
		}
		f.inputs[caseName] = input
	}

	return f, nil
}

func (f *itsFixture) close() {
	if f != nil && f.server != nil {
		f.server.Close()
	}
	if f != nil && f.tempDir != "" {
		_ = os.RemoveAll(f.tempDir)
	}
}

func (f *itsFixture) pushTaskBundle(bundleName string) (string, error) {
	ref, err := name.ParseReference(fmt.Sprintf("%s/acceptance/%s:1.0", f.registryHost, bundleName), name.Insecure)
	if err != nil {
		return "", fmt.Errorf("parse task bundle reference: %w", err)
	}
	if err := remote.Write(ref, empty.Image); err != nil {
		return "", fmt.Errorf("push task bundle %s: %w", bundleName, err)
	}
	digest, err := empty.Image.Digest()
	if err != nil {
		return "", fmt.Errorf("get task bundle digest: %w", err)
	}
	return fmt.Sprintf("%s/acceptance/%s@%s", f.registryHost, bundleName, digest), nil
}

func (f *itsFixture) publishCase(caseName string, runs []itsTestRun) (string, error) {
	repository := fmt.Sprintf("%s/acceptance/%s", f.registryHost, caseName)
	baseTag, err := name.ParseReference(repository+":image", name.Insecure)
	if err != nil {
		return "", fmt.Errorf("parse subject image reference: %w", err)
	}
	if err := remote.Write(baseTag, empty.Image); err != nil {
		return "", fmt.Errorf("push subject image: %w", err)
	}
	baseDigest, err := empty.Image.Digest()
	if err != nil {
		return "", fmt.Errorf("get subject digest: %w", err)
	}
	baseDescriptor, err := partial.Descriptor(empty.Image)
	if err != nil {
		return "", fmt.Errorf("get subject descriptor: %w", err)
	}

	for index, run := range runs {
		testResult := testResultStatement(repository, baseDigest, run.testName, run.timestamp)
		testResultBytes, err := json.Marshal(testResult)
		if err != nil {
			return "", fmt.Errorf("encode test result: %w", err)
		}
		testResultImage, err := testResultReferrer(testResultBytes, *baseDescriptor)
		if err != nil {
			return "", err
		}
		testResultDigest, err := testResultImage.Digest()
		if err != nil {
			return "", fmt.Errorf("get test result digest: %w", err)
		}
		testResultRef, err := name.NewDigest(fmt.Sprintf("%s@%s", repository, testResultDigest), name.Insecure)
		if err != nil {
			return "", fmt.Errorf("parse test result digest: %w", err)
		}
		if err := remote.Write(testResultRef, testResultImage); err != nil {
			return "", fmt.Errorf("push test result: %w", err)
		}

		if !run.includeProvenance {
			continue
		}
		invocationID := fmt.Sprintf("https://example.test/pipelineruns/%s-%d", caseName, index+1)
		provenance := slsaV1Statement(repository, testResultDigest, run.tasks, run.malformedProvenance, invocationID)
		if err := f.attachSignedProvenance(testResultRef, provenance); err != nil {
			return "", err
		}
	}

	policyInput := map[string]any{
		"attestations": []any{},
		"image": map[string]any{
			"digest": baseDigest.String(),
			"ref":    fmt.Sprintf("%s@%s", repository, baseDigest),
		},
		"snapshot": map[string]any{
			"application": "",
			"artifacts":   map[string]any{},
			"components":  []any{},
		},
	}
	inputBytes, err := json.Marshal(policyInput)
	if err != nil {
		return "", fmt.Errorf("encode policy input: %w", err)
	}
	return string(inputBytes), nil
}

func testResultReferrer(statement []byte, subject v1.Descriptor) (v1.Image, error) {
	layer := static.NewLayer(statement, types.MediaType(testResultArtifactType))
	image, err := ggcrmutate.AppendLayers(empty.Image, layer)
	if err != nil {
		return nil, fmt.Errorf("append test result layer: %w", err)
	}
	image = ggcrmutate.ConfigMediaType(image, types.MediaType(testResultArtifactType))
	withSubject, ok := ggcrmutate.Subject(image, subject).(v1.Image)
	if !ok {
		return nil, fmt.Errorf("test result referrer is not an image")
	}
	return withSubject, nil
}

func testResultStatement(repository string, subjectDigest v1.Hash, testName, timestamp string) map[string]any {
	return map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{
			"name":   repository,
			"digest": map[string]any{"sha256": subjectDigest.Hex},
		}},
		"predicateType": testResultPredicate,
		"predicate": map[string]any{
			"result":    "PASSED",
			"timestamp": timestamp,
			"configuration": []any{map[string]any{
				"name":   testName,
				"digest": map[string]any{"sha256": "7c3c9c77d93188f7b4a16dfed78f65d841fe31ec25c14c26b3fa67e0448a719e"},
			}},
			"url":         "https://example.test/integration/runs/1",
			"passedTests": []any{"clair-scan"},
			"warnedTests": []any{},
			"failedTests": []any{},
		},
	}
}
