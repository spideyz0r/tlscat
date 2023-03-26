package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"

	"github.com/pborman/getopt"
)

type TlsCat struct {
	crt      *x509.Certificate
	key      string
}

func main() {

	//tls-cat -c <file> -u url -s servername -p port -t timeout -k keyfile -v --verify
	help := getopt.BoolLong("help", 'h', "display this help")
	crt := getopt.StringLong("crt", 'c', "", "crt file")
	server := getopt.StringLong("server", 's', "", "remote server")
	server_name := getopt.StringLong("server-name", 'n', "", "optional server name")
	port := getopt.StringLong("port", 'p', "443", "optional port, default:80")
	key_file := getopt.StringLong("key-file", 'k', "", "key file")
	key_check := getopt.BoolLong("key-check", 'C', "private key validation")
	verbose := getopt.BoolLong("verbose", 'v', "verbose output")

	getopt.Parse()

	if *help {
		getopt.Usage()
		os.Exit(0)
	}

	var c TlsCat
	var err error

	stat, _ := os.Stdin.Stat()

	c.crt, err = readCertificate(*crt, *server, *port, *server_name, stat)
	if err != nil {
		log.Fatal(err)
	}

	if *key_check {
		err = c.keyCompare(*key_file, *verbose)
		if err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}
	c.printCertificate()
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

func readCertificate(crt, server, port, servername string, stat fs.FileInfo) (*x509.Certificate, error) {
	var cert []byte
	var err error

	if len(server) > 0 {
		config := &tls.Config{ InsecureSkipVerify: true }
		if len(servername) > 0 {
			config.ServerName = servername
		}
		conn, err := tls.Dial("tcp", server + ":" + port, config)
		if err != nil {
			return nil, fmt.Errorf("Failed to connect to %s:%s: %s\n", server, port, err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0], nil
	}

	if len(crt) >0{
		cert, err = ioutil.ReadFile(crt)
		if err != nil {
			return nil, fmt.Errorf("Failed to read certificate file: %s\n", err)
		}
	} else if (stat.Mode() & os.ModeCharDevice) == 0 {
		cert, err = ioutil.ReadAll(os.Stdin)
		if err != nil {
			return nil, fmt.Errorf("Failed to read certificate from stdin: %s\n", err)
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
