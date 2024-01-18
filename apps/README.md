# ACVP Proxy Application

The application provides a help output with the `-h` option.

## Configuration File

The ACVP Proxy application requires a configuration file. The default
configuration file is `acvpproxy_conf.json` and is located in the
current working directory. A different configuration file location
can be provided with the configuration option.

The ACVP Proxy allows accessing two different servers: the ACVP demo server
and the ACVP production server (when using `--official`). The configuration
file `acvpproxy_conf.json` is used with the ACVP demo server. When
trying to access the ACVP production server, configuration file
`acvpproxy_conf_production.json` is used unless overridden with
command line option. Both files have the same structure but allow maintaining
different credentials for both servers.

The configuration file is a JSON file with all of the following keywords
in the first hierarchy, for example:

```
{
	"tlsCaBundle": "bundle.pem",
	"tlsKeyFile": "key.pem",
	"tlsCertFile": "cert.pem.cer",
	"tlsKeyPasscode": "SomeSecurePasscode",

	"totpSeedFile": "acvp-seed.txt"
}
```

### Configuration File Keywords

* `tlsCaBundle`: The CA or the CA bundle in PEM format. This is optional. If
		 this configuration is not provided, no server validation is
		 performed.

* `tlsKeyFile`: TLS private client key in one of the allowed formats (see
		below). This entry is optional, e.g. when a P12 certificate
		is used that contains the private key. In such a case, the P12
		file with the public and private key will be added to
		`tlsCertFile`.

* `tlsCertFile`: TLS client certificate in one of the allowed formats (see
		 below)

* `tlsKeyPasscode`: Passcode used to protect the private key. This entry is
		    optional when the private key is not protected.

* `totpSeedFile`: Seed file holding the ACVP 2nd factor in Base64 format

The key types are identified based on the file suffix. The following suffixes
are allowed:

* .pem - PEM file

* .cer - PEM file

* .crt - DER file

* .der - DER file

* .p12 - P12 file - with Apple Secure Transport, this is the only allowed
  format. With Apple Secure Transport, the file path must start with "./"!

* .pfx - P12 file

### Creating CA Bundles

Ready-to-use CA bundles are present in the certs/ directory.

It may be possible that instead of having one CA certificate, you want to
use a certficate chain with more than one certificate, such as when a root
CA and intermediate CA certificate is required for the certificate validation.
In this case you must create a CA bundle and point to it with the configuration
option `tlsCaBundle`.

When creating such a bundle, you MUST ensure that the certificates with
dependencies are listed before those without dependencies.

To create a certificate bundle, simply concatenate them like the following:

`cat <intermediate.pem> > bundle.pem`

`cat <root.pem> >> bundle.pem`

### Using Apple Secure Transport

You can only use a PKCS12 bundle holding your private and public key.

To create a PKCS12 bundle and set it in the ACVP Proxy configuration file,
follow these steps:

* Create the PKCS12 bundle from your PEM or DER files (if you have a PKCS12
  bundle already, skip this step)

  `openssl pkcs12 -export -out <yourbundle>.p12 -inkey <yourprivatekey>.pem -in <yourcertificate>.pem -certificate <CAcert_or_CAbundle>.pem`

  The `-certificate` option is optional.

  During that command execution, you are requested to provide a password
  wrapping the PKCS12 bundle.

  NOTE: With newer openssl commands, use the `-legacy` option as otherwise the
  PKCS12 file is wrapped with AES which is not supported by macOS.

* Point to the PKCS12 bundle file with the `tlsCertFile` option and remove
  the `tlsKeyFile` option from the ACVP Proxy configuration file. Also, set
  your password in `tlsKeyPasscode` if you do not want to enter the
  passcode during each ACVP Proxy run.

  Note: During the first invocation of ACVP Proxy, macOS will ask you
  whether the ACVP Proxy is granted access to the key chain. Please approve
  as the PKCS12 bundle will be processed with the Apple Key Chain services.


### Apple Keychain Support

The ACVP Proxy compiled on macOS implements keychain support. The certificates
required by the ACVP Proxy to connect to the ACVP server can be completely
stored in the Apple keychain instead as a flat file on the disk. It is
recommended to use the Apple keychain instead of local key files.

If the Apple keychain shall be used, the ACVP server CA certificate as well
as the aforementioned PKCS#12 bundle with the client key/certificate must
be loaded into the keychain. The loading operation is not provided by the
ACVP Proxy (deliberately).

After the CA certificate and the PKCS#12 bundle are loaded into the keychain,
the ACVP Proxy configuration file must refer to those two entities with the
following configuration options:

* `tlsCaMacOSKeyChainRef`: This entry must contain the full string of the
			   ACVP server's CA certificate subject. When setting
			   this configuration option, it takes precedence over
			   `tlsCaBundle`. In this case, `tlsCaBundle` may be
			   removed from the configuration file. For example,
			   the following references are applicable:

	- ACVP demo server: `DigiCert SHA2 Secure Server CA`

	- ACVP production server: `acvp.nist.gov`

* `tlsCertMacOSKeyChainRef`: This configuration value refers to the full string
			     of the subject of the client certificate with
			     private key used for the TLS client authentication.
			     This configuration option takes precedence over
			     `tlsCertFile` and `tlsKeyFile` which may be
			     removed from the configuration file.

Note: The ACVP Proxy will perform an exact string match on the keychain
items noted above. If multiple keychain entries are resolved by this exact
string match (i.e. they have the exact same subject), the first matching
entry is used.

### NOTE


The configuration file will be expanded by a time stamp for the last TOTP use
by the ACVP Proxy. Please not not alter that value.

# Author

Stephan Mueller <smueller@chronox.de>
