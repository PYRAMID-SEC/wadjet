package scanner

import "testing"

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{name: "ws", target: "ws://localhost:8080/socket"},
		{name: "wss", target: "wss://example.com/socket"},
		{name: "http scheme", target: "http://localhost/socket", wantErr: true},
		{name: "missing host", target: "ws:///socket", wantErr: true},
		{name: "malformed", target: "://", wantErr: true},
		{name: "empty", target: "", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateURL(test.target)
			if (err != nil) != test.wantErr {
				t.Fatalf("ValidateURL(%q) error = %v, wantErr %v", test.target, err, test.wantErr)
			}
		})
	}
}
