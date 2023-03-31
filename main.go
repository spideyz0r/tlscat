package main

import (
	"log"
	"os"

	"github.com/pborman/getopt"
)

func main() {
	help := getopt.BoolLong("help", 'h', "display this help")
	crt := getopt.StringLong("crt", 'c', "", "crt file")
	server := getopt.StringLong("server", 's', "", "remote server")
	server_name := getopt.StringLong("server-name", 'n', "", "optional server name")
	port := getopt.StringLong("port", 'p', "443", "optional port, default:443")
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

	c.crt, err = ReadCertificate(*crt, *server, *port, *server_name, stat)
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
