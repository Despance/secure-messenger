package main

import (
	"crypto/x509"
	"testing"
)

func Test_parseCertificate(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		certBytes []byte
		want      *x509.Certificate
		wantErr   bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := parseCertificate(tt.certBytes)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("parseCertificate() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("parseCertificate() succeeded unexpectedly")
			}
			// TODO: update the condition below to compare got with tt.want.
			if true {
				t.Errorf("parseCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}
