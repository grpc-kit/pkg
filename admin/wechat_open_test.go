package admin

import (
	"encoding/json"
	"testing"
)

func TestWechatCode2SessionResponseIncludesUnionID(t *testing.T) {
	var response wechatCode2SessionResponse
	if err := json.Unmarshal([]byte(`{
		"session_key":"session-key",
		"openid":"openid-1",
		"unionid":"unionid-1"
	}`), &response); err != nil {
		t.Fatalf("unmarshal code2Session response: %v", err)
	}

	if response.Unionid != "unionid-1" {
		t.Fatalf("unionid mismatch: got %q", response.Unionid)
	}
}

func TestReconcileWechatUnionID(t *testing.T) {
	tests := []struct {
		name         string
		stored       string
		incoming     string
		wantValue    string
		wantPersist  bool
		wantConflict bool
	}{
		{
			name:      "ignore missing unionid",
			stored:    "stored-unionid",
			wantValue: "stored-unionid",
		},
		{
			name:        "backfill new unionid",
			incoming:    " unionid-1 ",
			wantValue:   "unionid-1",
			wantPersist: true,
		},
		{
			name:      "same unionid is unchanged",
			stored:    "unionid-1",
			incoming:  "unionid-1",
			wantValue: "unionid-1",
		},
		{
			name:         "conflicting unionid keeps stored value",
			stored:       "unionid-1",
			incoming:     "unionid-2",
			wantValue:    "unionid-1",
			wantConflict: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValue, gotPersist, gotConflict := reconcileWechatUnionID(tt.stored, tt.incoming)
			if gotValue != tt.wantValue || gotPersist != tt.wantPersist || gotConflict != tt.wantConflict {
				t.Fatalf(
					"reconcileWechatUnionID() = (%q, %t, %t), want (%q, %t, %t)",
					gotValue,
					gotPersist,
					gotConflict,
					tt.wantValue,
					tt.wantPersist,
					tt.wantConflict,
				)
			}
		})
	}
}
