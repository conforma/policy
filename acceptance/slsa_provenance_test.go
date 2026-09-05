// Copyright The Conforma Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/strfmt"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/cosign/v3/pkg/cosign/bundle"
	cosignmutate "github.com/sigstore/cosign/v3/pkg/oci/mutate"
	cosignremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	cosignstatic "github.com/sigstore/cosign/v3/pkg/oci/static"
	cosigntypes "github.com/sigstore/cosign/v3/pkg/types"
	rtypes "github.com/sigstore/rekor/pkg/types"
	rekordsse "github.com/sigstore/rekor/pkg/types/dsse"
	rekordsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	slsaProvenanceV1 = "https://slsa.dev/provenance/v1"
	tektonBuildType  = "https://tekton.dev/chains/v2/slsa-tekton"
)

func (f *itsFixture) attachSignedProvenance(subject name.Digest, statement map[string]any) error {
	payload, err := json.Marshal(statement)
	if err != nil {
		return fmt.Errorf("encode SLSA provenance: %w", err)
	}
	signer, err := cosign.LoadPrivateKey(f.signer.PrivateBytes, []byte{}, nil)
	if err != nil {
		return fmt.Errorf("load provenance signing key: %w", err)
	}
	envelopeSigner := dsse.WrapSigner(signer, cosigntypes.IntotoPayloadType)
	signedPayload, err := envelopeSigner.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("sign SLSA provenance: %w", err)
	}
	rekorBundle, err := f.rekorBundle(signedPayload)
	if err != nil {
		return fmt.Errorf("create transparency log bundle: %w", err)
	}
	attestation, err := cosignstatic.NewAttestation(
		signedPayload,
		cosignstatic.WithLayerMediaType(cosigntypes.DssePayloadType),
		cosignstatic.WithBundle(rekorBundle),
	)
	if err != nil {
		return fmt.Errorf("create provenance attestation: %w", err)
	}

	remoteOptions := []cosignremote.Option{
		cosignremote.WithNameOptions(name.Insecure),
		cosignremote.WithRemoteOptions(remote.WithContext(context.Background())),
	}
	signedEntity := cosignremote.SignedUnknown(subject, remoteOptions...)
	signedEntity, err = cosignmutate.AttachAttestationToEntity(signedEntity, attestation)
	if err != nil {
		return fmt.Errorf("attach provenance attestation: %w", err)
	}
	if err := cosignremote.WriteAttestations(subject.Repository, signedEntity, remoteOptions...); err != nil {
		return fmt.Errorf("push provenance attestation: %w", err)
	}
	return nil
}

// rekorBundle creates the offline-verifiable transparency-log material required
// by ec validate input. The matching generated public key is supplied to the ec
// subprocess through SIGSTORE_REKOR_PUBLIC_KEY.
func (f *itsFixture) rekorBundle(signedPayload []byte) (*bundle.RekorBundle, error) {
	publicKey := f.signer.PublicBytes
	proposedEntry, err := rtypes.NewProposedEntry(context.Background(), rekordsse.KIND, rekordsse_v001.APIVERSION, rtypes.ArtifactProperties{
		ArtifactBytes:  signedPayload,
		PublicKeyBytes: [][]byte{publicKey},
	})
	if err != nil {
		return nil, fmt.Errorf("create Rekor entry: %w", err)
	}
	entry, err := rtypes.UnmarshalEntry(proposedEntry)
	if err != nil {
		return nil, fmt.Errorf("decode Rekor entry: %w", err)
	}
	leaf, err := entry.Canonicalize(context.Background())
	if err != nil {
		return nil, fmt.Errorf("canonicalize Rekor entry: %w", err)
	}
	rekorPublicKey, err := f.rekorSigner.PublicKey(nil)
	if err != nil {
		return nil, fmt.Errorf("read Rekor public key: %w", err)
	}
	logID, err := cosign.GetTransparencyLogID(rekorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive Rekor log ID: %w", err)
	}
	payload := bundle.RekorPayload{
		Body:           base64.StdEncoding.EncodeToString(leaf),
		IntegratedTime: time.Now().Unix(),
		LogIndex:       1,
		LogID:          logID,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Rekor bundle payload: %w", err)
	}
	canonicalPayload, err := jsoncanonicalizer.Transform(payloadJSON)
	if err != nil {
		return nil, fmt.Errorf("canonicalize Rekor bundle payload: %w", err)
	}
	signedEntryTimestamp, err := f.rekorSigner.SignMessage(bytes.NewReader(canonicalPayload), options.WithContext(context.Background()))
	if err != nil {
		return nil, fmt.Errorf("sign Rekor bundle payload: %w", err)
	}
	return &bundle.RekorBundle{
		SignedEntryTimestamp: strfmt.Base64(signedEntryTimestamp),
		Payload:              payload,
	}, nil
}

func slsaV1Statement(repository string, subjectDigest v1.Hash, tasks []map[string]any, malformed bool, invocationID string) map[string]any {
	dependencies := make([]any, 0, len(tasks))
	for _, task := range tasks {
		content, _ := json.Marshal(task)
		dependencies = append(dependencies, map[string]any{
			"name":    "pipelineTask",
			"content": base64.StdEncoding.EncodeToString(content),
		})
	}
	if malformed {
		dependencies = []any{map[string]any{
			"name":    "pipelineTask",
			"content": "not-base64",
		}}
	}

	return map[string]any{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []any{map[string]any{
			"name":   repository,
			"digest": map[string]any{"sha256": subjectDigest.Hex},
		}},
		"predicateType": slsaProvenanceV1,
		"predicate": map[string]any{
			"buildDefinition": map[string]any{
				"buildType": tektonBuildType,
				"externalParameters": map[string]any{
					"runSpec": map[string]any{"pipelineSpec": map[string]any{}},
				},
				"internalParameters":   map[string]any{"labels": map[string]any{}, "annotations": map[string]any{}},
				"resolvedDependencies": dependencies,
			},
			"runDetails": map[string]any{
				"builder":  map[string]any{"id": "https://tekton.dev/chains/v2"},
				"metadata": map[string]any{"invocationId": invocationID},
			},
		},
	}
}

func slsaV1Task(taskName, bundle string) map[string]any {
	return map[string]any{
		"metadata": map[string]any{
			"name": taskName + "-taskrun",
			"labels": map[string]any{
				"tekton.dev/task":         taskName,
				"tekton.dev/pipelineTask": taskName,
			},
			"annotations": map[string]any{},
		},
		"spec": map[string]any{
			"params": []any{},
			"taskRef": map[string]any{
				"resolver": "bundles",
				"params": []any{
					map[string]any{"name": "name", "value": taskName},
					map[string]any{"name": "bundle", "value": bundle},
					map[string]any{"name": "kind", "value": "task"},
				},
			},
		},
		"status": map[string]any{
			"conditions": []any{map[string]any{
				"type": "Succeeded", "status": "True", "reason": "Succeeded",
			}},
			"results": []any{},
			"steps":   []any{},
		},
	}
}
