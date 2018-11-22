ACVP Proxy Application
======================

The application provides a help output with the `-h` option.

Configuration File
------------------

The ACVP Proxy application requires a configuration file. The default
configuration file is `acvpproxy_conf.json` and is located in the
current working directory. A different configuraiton file location
can be provided with the configuration option.

The configuration file is a JSON file with all of the following keywords
in the first hierarchy, for example:

```
{
	"tlsKeyFile": "key.pem",
	"tlsCertFile": "cert.pem.cer",
	"tlsKeyPasscode": "SomeSecurePasscode",

	"totpSeedFile": "acvp-seed.txt"
}
```

Configuration File Keywords
~~~~~~~~~~~~~~~~~~~~~~~~~~~

* `tlsKeyFile`: TLS private client key in one of the allowed formats (see
		below). This entry is optional, e.g. when a P12 certificate
		is used that contains the private key.

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

* .p12 - P12 file

* .pfx - P12 file

NOTE
~~~~

The configuration file will be expanded by a time stamp for the last TOTP use
by the ACVP Proxy. Please not not alter that value.

Author
======
Stephan Mueller <smueller@chronox.de>
