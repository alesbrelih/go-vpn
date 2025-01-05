package ca

import _ "embed"

//go:embed ca-key.pem
var KeyPEM []byte

//go:embed ca-cert.pem
var CertPEM []byte
