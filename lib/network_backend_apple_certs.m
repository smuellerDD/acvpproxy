/* Object encapsulating TLS client credential and server certificate
 *
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

#import <network_backend_apple_certs.h>

@implementation ACVPHTTPCerts

@synthesize clientCredential;
@synthesize serverCertificate;

/* Load server certificate */
- (CFArrayRef)loadServerCert:(const struct acvp_na_ex *)netinfo_ctx
{
	const struct acvp_net_ctx *net;
	
	if (!netinfo_ctx)
		return false;
		
	net = netinfo_ctx->net;
	
	//TODO: instead of getting cert from file, use keychain
	
	if (!net->certs_ca_file) {
		logger(LOGGER_ERR, LOGGER_C_CURL,
		       "No client certificate file available\n");
		return false;
	}
	
	if (strncasecmp(net->certs_ca_file_type, "DER", 3)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "The key file must be provided as a P12 file: key is provided of type %s\n",
		       net->certs_ca_file_type);
		return false;
	}
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL, "Using CA file %s\n",
	       net->certs_ca_file);
	NSData *caData = [[NSData alloc] initWithContentsOfFile:
			  [NSString stringWithFormat:@"%s",
			   net->certs_ca_file]];
	
	CFDataRef caDataRef = (__bridge CFDataRef)caData;
	SecCertificateRef caCert = SecCertificateCreateWithData(NULL,
								caDataRef);

	/* Create chain of trust anchored in cert */
	CFArrayRef caArrayRef = CFArrayCreate(NULL, (void *)&caCert, 1, NULL);
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL, "Server certificate loaded\n");
	
	return caArrayRef;
	
	/* TODO: Cleanup ? */
	//CFRelease(caArrayRef);
	//CFRelease(caCert);
	//CFRelease(caDataRef);
}

/* Load the client certificate from P12 file */
- (SecIdentityRef)loadClientCert:(const struct acvp_na_ex *)netinfo_ctx
{
	const struct acvp_net_ctx *net;
	SecIdentityRef clientCertificate = NULL;
	CFStringRef password = NULL;
	
	if (!netinfo_ctx)
		return NULL;
		
	net = netinfo_ctx->net;
	
	// TODO: Instead of loading client key from file, use keychain
	
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
		
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "Client key/certificate loaded\n");
	} else {
		logger(LOGGER_ERR, LOGGER_C_CURL, "Cannot load P12 file\n");
	}

	if (items) {
		CFRelease(items);
	}

	return clientCertificate;
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
