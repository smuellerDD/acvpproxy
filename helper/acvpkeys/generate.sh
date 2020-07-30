#!/bin/bash
#
# Generate a CSR to be sent to NIST for getting the
# certificate to access the NIST server
#

openssl genrsa -aes256 -out privkey-rsa.pem 4096
openssl req -config openssl-req.cnf -new -key privkey-rsa.pem -out atsec_corp-FIRSTNAME_LASTNAME-Demo.pem -sha256
