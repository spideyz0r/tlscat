package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"testing"
)

func TestReadCertificate(t *testing.T) {
	tests := []struct {
		crt        string
		server     string
		port       string
		servername string
		stat       os.FileInfo
		expected1  *x509.Certificate
		expected2  error
	}{
		{crt: "testdata/cert.pem", server: "", port: "", servername: "", stat: nil, expected1: nil, expected2: fmt.Errorf("Failed to read certificate file: open testdata/cert.pem: no such file or directory")},
	}

	fmt.Printf("tests: %v\n", tests)
	for _, test := range tests {
		actual1, actual2 := ReadCertificate(test.crt, test.server, test.port, test.servername, test.stat)
		// if actual1 != test.expected1 {
		if actual2 == nil {
			if actual1 != test.expected1 {
				t.Errorf("readCertificate(%q, %q, %q, %q, %q) returned %v, expected %v", test.crt, test.server, test.port, test.servername, test.stat, actual1, test.expected1)
			}
		}
		if (actual2 == nil) != (test.expected2 == nil) || (actual2 != nil && actual2.Error() != test.expected2.Error()) {
			t.Errorf("readCertificate(%q, %q, %q, %q, %q) returned error %v, expected error %v", test.crt, test.server, test.port, test.servername, test.stat, actual2, test.expected2)
		}
	}
}
