#!/bin/bash
#
# Generate a CSR to be sent to NIST for getting the
# certificate to access the NIST server
#
REQ=openssl-req.cnf
#REQ=openssl-req_acvp_prod.cnf

openssl genrsa -aes256 -out privkey-rsa.pem 4096
openssl req -config ${REQ} -new -key privkey-rsa.pem -out atseccorp_FIRSTNAME_LASTNAME-Demo.csr -sha256
