package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
)

type TlsCat struct {
	crt *x509.Certificate
	key string
}

func (c TlsCat) keyCompare(key_file string, verbose bool) error {
	cert_modulus := c.crt.PublicKey.(*rsa.PublicKey).N.String()
	k, err := ioutil.ReadFile(key_file)
	if err != nil {
		return fmt.Errorf("Failed to read key file: %s\n", err)
	}

	block, _ := pem.Decode(k)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("Failed to decode PEM block containing RSA private key")
	}

	pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("Failed to parse private key: %s\n", err)
	}
	modulus := pkey.N

	if verbose {
		fmt.Println("Private key modulus:", modulus)
		fmt.Println("Certificate key modulus:", cert_modulus)
	}
	if modulus.String() != cert_modulus {
		os.Exit(1)
	}
	os.Exit(0)
	return nil
}

func (c TlsCat) printCertificate() {
	fmt.Println("Certificate issuer:", c.crt.Issuer)
	fmt.Println("Certificate subject:", c.crt.Subject)
	fmt.Println("Certificate start date:", c.crt.NotBefore)
	fmt.Println("Certificate expiration date:", c.crt.NotAfter)
}

func ReadCertificate(crt, server, port, servername string, stat fs.FileInfo) (*x509.Certificate, error) {
	var cert []byte
	var err error

	if len(server) > 0 {
		config := &tls.Config{InsecureSkipVerify: true}
		if len(servername) > 0 {
			config.ServerName = servername
		}
		conn, err := tls.Dial("tcp", server+":"+port, config)
		if err != nil {
			return nil, fmt.Errorf("Failed to connect to %s:%s: %s", server, port, err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0], nil
	}

	if len(crt) > 0 {
		cert, err = ioutil.ReadFile(crt)
		if err != nil {
			return nil, fmt.Errorf("Failed to read certificate file: %s", err)
		}
	} else if (stat.Mode() & os.ModeCharDevice) == 0 {
		cert, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("Failed to read certificate from stdin: %s", err)
		}
	} else {
		return nil, fmt.Errorf("No certificate provided")
	}

	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, fmt.Errorf("Failed to decode certificate block")
	}

	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Error parsing certificate: %s", err)
	}
	return certificate, nil
}
