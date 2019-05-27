# OpenSSL / LibreSSL Threading Support

First of all: The ACVP Proxy does NOT use or rely on OpenSSL. Yet, it needs
to consider the shortcomings of OpenSSL in case OpenSSL is used by the
network backend. Per default, `libcurl` is used to provide HTTP support.
In turn, `libcurl` requires a crypto library for the TLS protocol. It is
usually the case that OpenSSL is used as TLS provider. This implies
that the ACVP Proxy uses OpenSSL indirectly in this case.

OpenSSL < 1.1.0 requires the caller to register callbacks when using it
in threaded applications. The code automatically registers the callbacks
for these older OpenSSL versions.

Also LibreSSL is subject to the same issue.

However, it requires that during link time libcrypto.so.
This requires a Makefile change where the variable LIBRARIES contains the
keyword "crypto". In this case, the Makefile must be manually changed to contain
the following line:

	LIBRARIES       := curl pthread crypto

WARNING: Even though the threading callbacks are set, crashes with OpenSSL
<= 1.0.2 in its error code handling has been observed using threading. Thus,
it is STRONGLY recommended that you either upgrade to OpenSSL >= 1.1.0
or you use libcurl with another TLS provider. Such fault has been observed
on MacOS when using the MacOS-provided libcurl with the MacOS-provided
libcrypto.dylib. It is currently unclear whether this issue is due to Apple's
libcrypto.dylib port or whether it is a general issue in OpenSSL.

This issue has not yet been observed on other platforms.

## Usable TLS Providers

The following TLS providers have been tested and proven to work reliably:

* OpenSSL 1.1.1

* Apple Secure Transport

* GnuTLS

* NSS

