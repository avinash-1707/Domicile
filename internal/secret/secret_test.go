package secret

import "testing"

func TestCheck(t *testing.T) {
	creds := map[string]string{"agent": "correct horse"}
	tests := []struct {
		name, user, pass string
		want             bool
	}{
		{"match", "agent", "correct horse", true},
		{"wrong password", "agent", "correct hors", false},
		{"unknown user", "nobody", "correct horse", false},
		{"unknown user empty password", "nobody", "", false},
		{"empty password for known user", "agent", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Check(creds, tt.user, tt.pass); got != tt.want {
				t.Fatalf("Check(%q, %q) = %v, want %v", tt.user, tt.pass, got, tt.want)
			}
		})
	}
}
