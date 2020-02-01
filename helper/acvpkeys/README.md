# Helper for Key Management

The following key management aspects are important to consider when
using ACVP:

1. Generation of a certificate signing request (CSR) that has a private
   and public key. The CSR with the public key is sent to NIST for signing
   to turn into a certificate.

2. Refer to the generated private key and the received certificate from the
   ACVP Proxy configuration:

	(a) set the tlsKeyFile to the PEM/DER private key file

	(b) set the tlsCertFile to the certificate

   On a macOS system, a P12 file must be used instead of individual PEM/DER
   files. This P12 file can be generated using the command listed below.
   The configuration file should contain the following in this case:

	(a) remove the tlsKeyFile key word from the configuation file

	(b) set the tlsCertFile to the P12 file

3. Add the CA certificate reference to tlsCaBundle. Note, on macOS systems
   this file MUST be a DER file. A PEM file can be converted with the following
   command:

	`openssl x509 -inform PEM -outform DER -in acvp.nist.gov.crt -out acvp.nist.gov.der`

## Generate CSR for NIST

To generate a CSR, perform the following steps

1. Modify the openssl-req.cnf to point to the intended DN components

2. Invoke the generate.sh script

## Create P12 File

Using the generated private key and the obtained certificate from NIST,
the P12 file can be obtained with the following command:

openssl pkcs12 -export -out acvpproxy_keybundle.p12 -inkey privkey-rsa.pem -in NIST-provided-certificate.crt

The command requires a password to protect the P12 file. Set this password
with the tlsKeyPasscode configuration option.
