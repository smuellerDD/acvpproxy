OpenSSL Threading Support
=========================

First of all: The ACVP Proxy does NOT use or rely on OpenSSL. Yet, it needs
to consider the shortcomings of OpenSSL in case OpenSSL is used by the
network backend. Per default, `libcurl` is used to provide HTTP support.
In turn, `libcurl` requires a crypto library for the TLS protocol. It is
usually the case that OpenSSL is used as TLS provider. This implies
that the ACVP Proxy uses OpenSSL indirectly in this case.

OpenSSL < 1.1.0 requires the caller to register callbacks when using it
in threaded applications. The code automatically registers the callbacks
for these older OpenSSL versions.

However, it requires that during link time libcrypto.so.
This requires a Makefile change where the variable LIBRARIES contains the
keyword "crypto". In this case, the Makefile must be manually changed to contain
the following line:

	LIBRARIES       := curl pthread crypto
