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

package asciidoc

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFormatTime(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{
			name:     "time.Time with UTC timezone",
			input:    time.Date(2023, 8, 31, 0, 0, 0, 0, time.UTC),
			expected: "2023-08-31T00:00:00Z",
		},
		{
			name:     "time.Time with non-UTC timezone",
			input:    time.Date(2023, 8, 31, 10, 30, 45, 0, time.FixedZone("EST", -5*3600)),
			expected: "2023-08-31T10:30:45-05:00",
		},
		{
			name:     "time.Time with nanoseconds",
			input:    time.Date(2023, 8, 31, 12, 0, 0, 123456789, time.UTC),
			expected: "2023-08-31T12:00:00Z", // RFC3339 format omits nanoseconds when formatting time.Time
		},
		{
			name:     "RFC3339 string with Z timezone",
			input:    "2023-08-31T00:00:00Z",
			expected: "2023-08-31T00:00:00Z",
		},
		{
			name:     "RFC3339 string with numeric timezone",
			input:    "2023-08-31T10:30:45-05:00",
			expected: "2023-08-31T10:30:45-05:00",
		},
		{
			name:     "RFC3339 string with nanoseconds",
			input:    "2023-08-31T12:00:00.123456789Z",
			expected: "2023-08-31T12:00:00Z", // Parsed and reformatted, RFC3339 format omits nanoseconds
		},
		{
			name:     "RFC3339 string with fractional seconds",
			input:    "2021-01-01T00:00:00.000Z",
			expected: "2021-01-01T00:00:00Z",
		},
		{
			name:     "non-RFC3339 string",
			input:    "not a timestamp",
			expected: "not a timestamp",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "integer",
			input:    42,
			expected: "42",
		},
		{
			name:     "float",
			input:    3.14,
			expected: "3.14",
		},
		{
			name:     "boolean true",
			input:    true,
			expected: "true",
		},
		{
			name:     "boolean false",
			input:    false,
			expected: "false",
		},
		{
			name:     "nil",
			input:    nil,
			expected: "<nil>",
		},
		{
			name:     "string with timestamp-like format but invalid",
			input:    "2023-13-32T25:61:61Z",
			expected: "2023-13-32T25:61:61Z",
		},
		{
			name:     "non-RFC3339 time-like string returned unchanged",
			input:    "2023-08-31 00:00:00 +0000 UTC",
			expected: "2023-08-31 00:00:00 +0000 UTC",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatTime(tt.input)
			if result != tt.expected {
				t.Errorf("formatTime(%v) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestFormatTimeConsistency(t *testing.T) {
	// Test that time.Time and equivalent RFC3339 string produce the same output
	timestamp := time.Date(2023, 8, 31, 0, 0, 0, 0, time.UTC)
	timestampString := "2023-08-31T00:00:00Z"

	resultFromTime := formatTime(timestamp)
	resultFromString := formatTime(timestampString)

	if resultFromTime != resultFromString {
		t.Errorf("Inconsistent formatting: time.Time produced %q but string produced %q",
			resultFromTime, resultFromString)
	}

	if resultFromTime != timestampString {
		t.Errorf("Expected %q but got %q", timestampString, resultFromTime)
	}
}

func TestFormatTimeRoundTrip(t *testing.T) {
	// Test that formatting a time.Time and then parsing it back produces the same time
	original := time.Date(2023, 8, 31, 10, 30, 45, 0, time.UTC)
	formatted := formatTime(original)
	parsed, err := time.Parse(time.RFC3339, formatted)

	if err != nil {
		t.Fatalf("Failed to parse formatted time %q: %v", formatted, err)
	}

	if !original.Equal(parsed) {
		t.Errorf("Round-trip failed: original %v != parsed %v", original, parsed)
	}
}

func TestRemoveAdocFiles(t *testing.T) {
	t.Run("removes .adoc files", func(t *testing.T) {
		dir := t.TempDir()

		// Create .adoc files
		for _, name := range []string{"release_foo.adoc", "pipeline_bar.adoc"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("content"), 0644); err != nil {
				t.Fatal(err)
			}
		}

		if err := removeAdocFiles(dir); err != nil {
			t.Fatalf("removeAdocFiles() returned error: %v", err)
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Errorf("expected empty directory, got %d entries", len(entries))
		}
	})

	t.Run("preserves non-adoc files", func(t *testing.T) {
		dir := t.TempDir()

		// Create a mix of files
		if err := os.WriteFile(filepath.Join(dir, "stale.adoc"), []byte("stale"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("keep"), 0644); err != nil {
			t.Fatal(err)
		}

		if err := removeAdocFiles(dir); err != nil {
			t.Fatalf("removeAdocFiles() returned error: %v", err)
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].Name() != "keep.txt" {
			t.Errorf("expected keep.txt, got %s", entries[0].Name())
		}
	})

	t.Run("preserves subdirectories", func(t *testing.T) {
		dir := t.TempDir()

		subDir := filepath.Join(dir, "subdir")
		if err := os.Mkdir(subDir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "stale.adoc"), []byte("stale"), 0644); err != nil {
			t.Fatal(err)
		}

		if err := removeAdocFiles(dir); err != nil {
			t.Fatalf("removeAdocFiles() returned error: %v", err)
		}

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 entry, got %d", len(entries))
		}
		if entries[0].Name() != "subdir" || !entries[0].IsDir() {
			t.Errorf("expected subdir directory, got %s", entries[0].Name())
		}
	})

	t.Run("nonexistent directory is not an error", func(t *testing.T) {
		if err := removeAdocFiles(filepath.Join(t.TempDir(), "nonexistent")); err != nil {
			t.Fatalf("removeAdocFiles() returned error for nonexistent dir: %v", err)
		}
	})

	t.Run("empty directory is not an error", func(t *testing.T) {
		if err := removeAdocFiles(t.TempDir()); err != nil {
			t.Fatalf("removeAdocFiles() returned error for empty dir: %v", err)
		}
	})
}
