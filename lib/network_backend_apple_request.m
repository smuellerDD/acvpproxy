/* Invocation of NSURLSession network operation and TLS authentiation handling
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

#import <network_backend_apple_request.h>

#include "logger.h"
#include "sleep.h"

static ACVPHTTPCerts *acvp_certs = NULL;
static atomic_bool_t task_complete = ATOMIC_BOOL_INIT(false);

@implementation ACVPHTTPRequest

/* Delegates for debugging */
- (void)  URLSession:(NSURLSession *)session
		task:(NSURLSessionTask *)task
didCompleteWithError:(NSError *)error
{
	(void)session;
	(void)task;
	if (error == nil)
		return;
	
	logger(LOGGER_WARN, LOGGER_C_CURL, "Received networking error %s\n",
	       error.localizedDescription.UTF8String);
}

- (void)loggingrequest:(NSURLRequest *)request
{
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "\n* Network port %u\n"
	       "* Schema %s\n"
	       "* URL %s\n"
	       "* HTTP method %s\n"
	       "* HTTP header %s\n"
	       "* HTTP body %s\n",
	       request.URL.port.unsignedIntValue,
	       request.URL.scheme.UTF8String,
	       request.URL.absoluteString.UTF8String,
	       request.HTTPMethod.UTF8String,
	       request.allHTTPHeaderFields.description.UTF8String,
	       request.HTTPBody.description.UTF8String);
}

- (void)URLSession:(NSURLSession *)session
	      task:(NSURLSessionTask *)task
   didSendBodyData:(int64_t)bytesSent
    totalBytesSent:(int64_t)totalBytesSent
totalBytesExpectedToSend:(int64_t)totalBytesExpectedToSend
{
	(void)session;
	(void)task;
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "Sending progress - data sent: %ld, total data sent: %ld, message size: %ld bytes\n",
	       bytesSent, totalBytesSent,
	       totalBytesExpectedToSend);
	
	//logger(LOGGER_DEBUG, LOGGER_C_CURL, "Current request:\n");
	//[self loggingrequest:task.currentRequest];
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL, "Request:\n");
	[self loggingrequest:task.originalRequest];
}

- (void)URLSession:(NSURLSession *)session
taskIsWaitingForConnectivity:(NSURLSessionTask *)task
{
	(void)session;
	(void)task;
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "Waiting for connectivity to start HTTP operation\n");
}

/* Networking operation */

/* Perform the trust validation of the server certificate */
- (BOOL)validateServerCert:(NSURLProtectionSpace *)protectionSpace
{
	SecTrustRef serverTrust = protectionSpace.serverTrust;
	SecTrustSetAnchorCertificates(serverTrust,
				      acvp_certs.serverCertificate);

	/* Verify trust */
	bool trustResult = SecTrustEvaluateWithError(serverTrust, nil);
	
	if (trustResult) {
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Server certificate validation succeeded - server trusted\n");
	} else {
		logger(LOGGER_ERR, LOGGER_C_CURL,
		       "Server certificate validation failed\n");
	}

	/* Was trust chain evaluation successful? */
	return trustResult;
}

/*
 * NSURLSessionDelegate callback implementing the authentication challenge of
 * SSL client authentication.
 */
- (void) URLSession:(NSURLSession *)session
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
  completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition,
			      NSURLCredential *credential))completionHandler
{
	(void)session;
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "Session authentication challenge received of type %s (previous error code %d)\n",
	       challenge.protectionSpace.authenticationMethod.UTF8String,
	       challenge.error.code);
	
	/* Return client certificate for authentication */
	if ([challenge.protectionSpace.authenticationMethod
	     isEqualToString:NSURLAuthenticationMethodClientCertificate]) {
		NSURLCredential *credential = acvp_certs.clientCredential;
		
		if (credential) {
			logger(LOGGER_DEBUG, LOGGER_C_CURL,
			       "Setting private key\n");
			completionHandler(NSURLSessionAuthChallengeUseCredential,
					  credential);
			return;
		}
	}
	
	/* Validate server */
	if ([challenge.protectionSpace.authenticationMethod
	     isEqualToString:NSURLAuthenticationMethodServerTrust]) {
		if ([self validateServerCert:challenge.protectionSpace]) {
			completionHandler(NSURLSessionAuthChallengeUseCredential,
					  [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
			return;
		} else {
		completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge,
			NULL);
		}
	}
	
	completionHandler(NSURLSessionAuthChallengePerformDefaultHandling,
			  NULL);
}

/*
* NSURLSessionDelegate callback
*/
- (void)URLSession:(NSURLSession *)session
didBecomeInvalidWithError:(NSError *)error
{
	(void)session;
	logger(LOGGER_DEBUG, LOGGER_C_CURL, "didBecomeInvalidWithError %ld\n",
	       error.code);
}

- (long) sendRequestFromURL: (NSMutableURLRequest *)urlRequest
		interrupted: (atomic_bool_t *)interrupted
	       response_buf: (struct acvp_buf *)response_buf
		 completion: (void (^)(struct acvp_buf *,
				       atomic_bool_t *,
				       NSData *,
				       NSURLResponse *,
				       NSError *)) completion
{
	NSURLSessionConfiguration *defaultConfigObject;
	NSURLSession *defaultSession;
	long ret;
	
	if (completion == nil)
		return -EFAULT;
	
	defaultConfigObject = [NSURLSessionConfiguration
			       defaultSessionConfiguration];
	defaultSession = [NSURLSession
			  sessionWithConfiguration:defaultConfigObject
			  delegate:self
			  delegateQueue:nil];
	
	defaultConfigObject.waitsForConnectivity = true;
				      
	NSURLSessionDataTask *task = [defaultSession
				      dataTaskWithRequest:urlRequest
				      completionHandler:^(NSData *data,
							  NSURLResponse *response,
							  NSError *error)
	{
		atomic_bool_set_false(&task_complete);
		completion(response_buf, &task_complete, data, response, error);
	}];
	
	[task resume];
	
	/*
	 * TODO instead of using the hack below, wait for the completion
	 * task to finish. Yet, this completion is triggered before the task
	 * should complete. I am not sure about how to solve it.
	 */
#if 0
	/*
	 * If we time out here, kill the task as something happened. We expect
	 * that all server interaction for one request completes within this
	 * time frame.
	 */
	ret = sleep_interruptible2(300, interrupted, &task_complete);
	if (!ret) {
		[task cancel];
	}
#endif

	while (task.state != NSURLSessionTaskStateCompleted &&
	       task.state != NSURLSessionTaskStateCanceling) {
		int ret2;

		/*
		 * Do not reuse the variable ret as it must be left
		 * untouched in case it contains the error from the
		 * HTTP operation.
		 */
		/*
		 * TODO this is an aweful hack to wait for the completion of
		 * the task. Yet, it is not as problematic timewise as we
		 * execute in a separate thread and thus the one second
		 * maximum wait time is negligable. Question is: how can
		 * we wait for the task to complete?
		 */
		ret2 = sleep_interruptible(1, interrupted);
		if (ret2 < 0) {

			/* Cancel task if it is still running */
			if (task.state != NSURLSessionTaskStateCompleted &&
			    task.state != NSURLSessionTaskStateCanceling)
				[task cancel];

			break;
		}
	}
	
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "HTTP task completed - total data sent: %ld, total data received: %ld bytes\n",
	       task.countOfBytesSent, task.countOfBytesReceived);
	
	if (task.error != nil && task.error.code) {
		[defaultSession invalidateAndCancel];
		return -task.error.code;
	}
	
	NSHTTPURLResponse *http_response = (NSHTTPURLResponse *)task.response;
	ret = http_response.statusCode;
	[defaultSession finishTasksAndInvalidate];
	return ret;
}

- (id)initWithCerts:(ACVPHTTPCerts *)initCerts
{
	self = [super init];

	if (self) {
		acvp_certs = initCerts;
	}
	
	return self;
}

@end
