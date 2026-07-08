package auth

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// sharedGRNMatchCase 是 Go / Rego 两侧 GRN Match 行为对齐使用的共享用例结构。
// JSON schema 见 testdata/grn_match.json。
type sharedGRNMatchCase struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Want    string `json:"want"`
	WantOk  bool   `json:"wantOk"`
}

type sharedGRNMatchFile struct {
	Cases []sharedGRNMatchCase `json:"cases"`
}

// loadSharedMatchCases 从 testdata 读取与 Rego 共享的 GRN Match 用例集。
func loadSharedMatchCases(t *testing.T) []sharedGRNMatchCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "grn_match.json"))
	if err != nil {
		t.Fatalf("read shared grn_match testdata: %v", err)
	}
	var f sharedGRNMatchFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse shared grn_match testdata: %v", err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("shared grn_match testdata: empty cases")
	}
	return f.Cases
}

// TestMatch_SharedWithRego 跑共享 testdata，确保 Go 端 Match 与 spec/grn.md
// §8 验收清单 + Rego 端 grn_match 行为一致。
func TestMatch_SharedWithRego(t *testing.T) {
	for _, c := range loadSharedMatchCases(t) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			got := Match(c.Pattern, c.Want)
			if got != c.WantOk {
				t.Errorf("Match(%q, %q) = %v, want %v", c.Pattern, c.Want, got, c.WantOk)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		wantGRN *GRN
	}{
		{
			name:  "canonical_with_path",
			input: "grn:grpc-kit:svc:r:a:type/path",
			wantGRN: &GRN{
				Partition: "grpc-kit",
				Service:   "svc",
				Region:    "r",
				Account:   "a",
				Resource:  "type/path",
			},
		},
		{
			name:  "platform_empty_region_account",
			input: "grn:grpc-kit:admin.v1.known:::services/x",
			wantGRN: &GRN{
				Partition: "grpc-kit",
				Service:   "admin.v1.known",
				Region:    "",
				Account:   "",
				Resource:  "services/x",
			},
		},
		{
			name:  "resource_segment_keeps_colons",
			input: "grn:grpc-kit:svc:r:a:type/path:with:colons",
			wantGRN: &GRN{
				Partition: "grpc-kit",
				Service:   "svc",
				Region:    "r",
				Account:   "a",
				Resource:  "type/path:with:colons",
			},
		},
		{
			name:    "missing_segments",
			input:   "grn:grpc-kit:svc:r:a",
			wantErr: true,
		},
		{
			name:    "wrong_scheme",
			input:   "arn:grpc-kit:svc:r:a:type/x",
			wantErr: true,
		},
		{
			name:    "empty_partition",
			input:   "grn::svc:r:a:type/x",
			wantErr: true,
		},
		{
			name:    "empty_string",
			input:   "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Parse(%q): expected error, got nil", tt.input)
				}
				if !errors.Is(err, ErrInvalidGRN) {
					t.Errorf("Parse(%q): error %v not wrapping ErrInvalidGRN", tt.input, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse(%q): unexpected error %v", tt.input, err)
			}
			if *got != *tt.wantGRN {
				t.Errorf("Parse(%q) = %+v, want %+v", tt.input, got, tt.wantGRN)
			}
			// round-trip 校验
			if rt := got.String(); rt != tt.input {
				t.Errorf("round-trip String() = %q, want %q", rt, tt.input)
			}
		})
	}
}

func TestNormalizePartition(t *testing.T) {
	if got := NormalizePartition(""); got != DefaultPartition {
		t.Errorf("NormalizePartition(\"\") = %q, want %q", got, DefaultPartition)
	}
	if got := NormalizePartition(PartitionCN); got != PartitionCN {
		t.Errorf("NormalizePartition(%q) = %q, want unchanged", PartitionCN, got)
	}
}

// TestGlobMatch_Internal 直接覆盖 globMatch 的几个关键语义边界。
func TestGlobMatch_Internal(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
		ok      bool
	}{
		{"host/*", "host/sw-01", true},
		{"host/*", "host/cluster/sw-01", false}, // 单 * 不跨 /
		{"host/**", "host/cluster/sw-01", true}, // 双 * 可跨 /
		{"host/sw-bj-*", "host/sw-bj-01", true},
		{"host/sw-bj-*", "host/sw-sh-01", false},
		{"a/?/c", "a/b/c", true},
		{"a/?/c", "a//c", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"*", "anything", true},
		{"*", "with/slash", false},
		{"**", "with/slash", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.pattern+"_vs_"+tt.want, func(t *testing.T) {
			if got := globMatch(tt.pattern, tt.want, '/'); got != tt.ok {
				t.Errorf("globMatch(%q, %q, '/') = %v, want %v", tt.pattern, tt.want, got, tt.ok)
			}
		})
	}
}
