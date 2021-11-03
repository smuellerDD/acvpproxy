# Certificates

The certificates in this directory are relevant for the interaction with the
ACVP server in case the client wants to validate the server's authenticity.

The following certificates can be added to the `acvpproxy_conf.json` file's
`tlsCaBundle` configuration option, if a server certificate validation
is intended. It is strongly suggested to perform the server certificate
authentication.

The following certificates are present:

* `digitcert_bundle.pem`: Certificate chain bundle used for ACVP demo server
  as well as the ACVP production server
