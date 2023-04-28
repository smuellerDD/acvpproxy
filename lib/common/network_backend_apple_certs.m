/* Object encapsulating TLS client credential and server certificate
 *
 * Copyright (C) 2020 - 2023, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#import "network_backend_apple_certs.h"

@implementation ACVPHTTPCerts

@synthesize clientCredential;
@synthesize serverCertificate;

/* Load server certificate from keychain */
- (SecCertificateRef)loadServerCertKeyChain:(const char *)cert_reference
{
	if (!cert_reference)
		return nil;
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "Searching keychain for server certificate: %s\n",
	       cert_reference);
	
	NSDictionary* clientCertificateQuery =
		@{(id)kSecMatchLimit: (id)kSecMatchLimitAll,
		  (id)kSecClass: (id)kSecClassCertificate,
		  (id)kSecMatchSubjectWholeString:
			  [NSString stringWithFormat:@"%s", cert_reference],
		  (id)kSecReturnRef: (id)kCFBooleanTrue};
	SecCertificateRef cert = NULL;
	OSStatus err = SecItemCopyMatching(
			(__bridge CFDictionaryRef) clientCertificateQuery,
			(CFTypeRef *)&cert);
	if (err != errSecSuccess) {
		CFStringRef errstr = SecCopyErrorMessageString(err, NULL);

		if (!errstr)
			return nil;

		logger(LOGGER_ERR, LOGGER_C_CURL,
		       "Could not locate private key %s in keychain: %s\n",
		       cert_reference,
		       CFStringGetCStringPtr(errstr, kCFStringEncodingUTF8));
		CFRelease(errstr);
		if (cert)
			CFRelease(cert);
		return nil;
	}
	
	return cert;
}

/* Load server certificate from file */
- (SecCertificateRef)loadServerCertFromFile:(const struct acvp_net_ctx *)net
{
	if (!net->certs_ca_file) {
		logger(LOGGER_ERR, LOGGER_C_CURL,
		       "No server certificate file available for verification\n");
		return nil;
	}
	
	if (strncasecmp(net->certs_ca_file_type, "DER", 3)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "The key file must be provided as a DER file: key is provided of type %s\n",
		       net->certs_ca_file_type);
		return nil;
	}
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL, "Using CA file %s\n",
	       net->certs_ca_file);
	NSData *caData = [[NSData alloc] initWithContentsOfFile:
			  [NSString stringWithFormat:@"%s",
			   net->certs_ca_file]];
	
	CFDataRef caDataRef = (__bridge CFDataRef)caData;
	SecCertificateRef caCert = SecCertificateCreateWithData(NULL,
								caDataRef);

	return caCert;
}

- (CFArrayRef)loadServerCert:(const struct acvp_na_ex *)netinfo_ctx
{
	const struct acvp_net_ctx *net;
	SecCertificateRef caCert = nil;

	if (!netinfo_ctx)
		return nil;

	net = netinfo_ctx->net;

	if (net->certs_ca_macos_keychain_ref)
		caCert = [self loadServerCertKeyChain:net->certs_ca_macos_keychain_ref];
	else
		caCert = [self loadServerCertFromFile:net];

	if (caCert == nil)
		return nil;

	/* Create chain of trust anchored in cert */
	CFArrayRef caArrayRef = CFArrayCreate(NULL, (void *)&caCert, 1, NULL);
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL, "Server certificate loaded\n");
	
	return caArrayRef;
}

/* Load the client certificate / private key from keychain */
- (SecIdentityRef)loadClientCertKeyChain:(const char *)cert_reference
{
	if (!cert_reference)
		return nil;

	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "Searching keychain for client key / certificate: %s\n",
	       cert_reference);

	NSDictionary* clientCertificateQuery =
		@{(id)kSecMatchLimit: (id)kSecMatchLimitOne,
		  (id)kSecClass: (id)kSecClassIdentity,
		  (id)kSecMatchSubjectWholeString:
			  [NSString stringWithFormat:@"%s", cert_reference],
		  (id)kSecUseOperationPrompt:
			  [NSString stringWithFormat:@"Allow ACVP Proxy to use key for TLS client authentication"],
		  (id)kSecReturnRef: (id)kCFBooleanTrue};
	SecIdentityRef identity = NULL;
	OSStatus err = SecItemCopyMatching(
			(__bridge CFDictionaryRef) clientCertificateQuery,
			(CFTypeRef *)&identity);

	if (err != errSecSuccess) {
		logger(LOGGER_ERR, LOGGER_C_CURL,
		       "Could not locate private key %s in keychain: %s\n",
		       cert_reference,
		       CFStringGetCStringPtr(SecCopyErrorMessageString(err, NULL),
					     kCFStringEncodingUTF8));
	}
	
	return identity;
}

/* Load the client certificate / private key from P12 file */
- (SecIdentityRef)loadClientCertFromFile:(const struct acvp_net_ctx *)net
{
	SecIdentityRef clientCertificate = NULL;
	CFStringRef password = NULL;
	
	if (!net->certs_clnt_file) {
		logger(LOGGER_ERR, LOGGER_C_CURL,
		       "No client certificate file available\n");
		return NULL;
	}
	
	if (strncasecmp(net->certs_clnt_file_type, "P12", 3)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "The key file must be provided as a P12 file: key is provided of type %s\n",
		       net->certs_clnt_file_type);
		return NULL;
	}

	logger(LOGGER_DEBUG, LOGGER_C_CURL, "Using key file %s\n",
	       net->certs_clnt_file);
	NSData *pkcs12Data = [[NSData alloc]
			      initWithContentsOfFile:[NSString
						      stringWithFormat:@"%s",
						      net->certs_clnt_file]];

	CFDataRef inPKCS12Data = (__bridge CFDataRef)pkcs12Data;
	
	if (net->certs_clnt_passcode) {
		password = CFStringCreateWithCString(NULL,
						     net->certs_clnt_passcode,
						     kCFStringEncodingUTF8);
	}
	
	const void *keys[] = { kSecImportExportPassphrase };
	const void *values[] = { password };
	CFDictionaryRef optionsDictionary =
			CFDictionaryCreate(NULL, keys, values,
					   net->certs_clnt_passcode ? 1 : 0,
					   NULL, NULL);
	CFArrayRef items = NULL;

	OSStatus err = SecPKCS12Import(inPKCS12Data, optionsDictionary, &items);

	CFRelease(optionsDictionary);
	
	if (password)
		CFRelease(password);

	if (err == errSecSuccess && CFArrayGetCount(items) > 0) {
		CFDictionaryRef pkcsDict = CFArrayGetValueAtIndex(items, 0);

		SecTrustRef trust = (SecTrustRef)CFDictionaryGetValue(
					pkcsDict, kSecImportItemTrust);

		if (trust != NULL) {
			clientCertificate = (SecIdentityRef)CFDictionaryGetValue(
						pkcsDict,
						kSecImportItemIdentity);
			CFRetain(clientCertificate);
		}
		
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Client key/certificate loaded\n");
	} else {
		logger(LOGGER_ERR, LOGGER_C_CURL, "Cannot load P12 file: %s\n",
		       CFStringGetCStringPtr(SecCopyErrorMessageString(err, NULL),
					     kCFStringEncodingUTF8));
	}

	if (items) {
		CFRelease(items);
	}

	return clientCertificate;
}

- (SecIdentityRef)loadClientCert:(const struct acvp_na_ex *)netinfo_ctx
{
	const struct acvp_net_ctx *net;

	if (!netinfo_ctx)
		return NULL;

	net = netinfo_ctx->net;

	if (net->certs_clnt_macos_keychain_ref)
		return [self loadClientCertKeyChain:net->certs_clnt_macos_keychain_ref];

	return [self loadClientCertFromFile:net];
}

/* Return the client credential for the authentication callback */
- (NSURLCredential *)getClientCredential:(const struct acvp_na_ex *)netinfo_ctx
{
	SecIdentityRef identity = [self loadClientCert:netinfo_ctx];

	if (!identity) {
		return nil;
	}

	SecCertificateRef certificate = NULL;
	SecIdentityCopyCertificate (identity, &certificate);
	const void *certs[] = {certificate};
	CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1,
					     NULL);
	NSURLCredential *credential =
		[NSURLCredential
		 credentialWithIdentity:identity
		 certificates:(__bridge NSArray *)certArray
		 persistence:NSURLCredentialPersistenceForSession];
	CFRelease(certArray);
	
	CFRelease(identity);

	return credential;
}

- (id)initWithNetinfo:(const struct acvp_na_ex *)netinfo
{
	self = [super init];

	if (self) {
		clientCredential = [self getClientCredential:netinfo];
		serverCertificate = [self loadServerCert:netinfo];
	}
	
	return self;
}

@end
