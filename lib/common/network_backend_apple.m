/* Network access backend using Apple NSURL framework
 *
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <CFNetwork/CFNetwork.h>
#import <Foundation/Foundation.h>
#import "network_backend_apple_request.h"

#include "atomic_bool.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "sleep.h"

#define ACVP_CURL_MAX_RETRIES	3

/*
 * Shall the ACVP operation be shut down?
 */
static atomic_bool_t acvp_nsurl_interrupted = ATOMIC_BOOL_INIT(false);

static ACVPHTTPCerts *acvp_certs = NULL;
static DEFINE_MUTEX_UNLOCKED(acvp_certs_lock);

static void acvp_nsurl_interrupt(void)
{
	atomic_bool_set_true(&acvp_nsurl_interrupted);
}

static void acvp_nsurl_write_cb(struct acvp_buf *response_buf,
				atomic_bool_t *task_complete,
				NSData *data,
				NSURLResponse *response,
				NSError *error)
{
	size_t bufsize, totalsize;
	uint8_t *resp_p;
	NSString *text;
	NSHTTPURLResponse *http_response = (NSHTTPURLResponse *)response;
	const char *ptr;
	
	if (error != nil || response == nil || data == nil)
		goto out;
	
	if (http_response.statusCode < 200 ||
	    http_response.statusCode >= 300) {
		logger(LOGGER_ERR, LOGGER_C_CURL,
		       "HTTP error status code: %lu\n",
		       (unsigned long)http_response.statusCode);
		/*
		 * We do not goto out here because we want the response data
		 * from the server (if there is any) to be send to the caller.
		 */
	}
	
	text = [[NSString alloc] initWithData: data
				     encoding: NSUTF8StringEncoding];
	if (text == nil)
		goto out;

	bufsize = text.length;
	ptr = text.UTF8String;

	if (!response_buf) {
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Retrieved data size : %zu\n", bufsize);
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "Retrieved data: %s\n",
		       ptr);
		goto out;
	}

	if (!bufsize)
		goto out;

	totalsize = bufsize + response_buf->len;
	if (totalsize > ACVP_RESPONSE_MAXLEN || totalsize < response_buf->len) {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Received data is too big: %zu\n", totalsize);
		goto out;
	}

	if (!response_buf->buf)
		response_buf->buf = malloc(bufsize + 1); /* add one for \0 */
	else
		response_buf->buf = realloc(response_buf->buf, totalsize + 1);

	if (!response_buf->buf) {
		response_buf->len = 0;
		goto out;
	}

	resp_p = response_buf->buf + response_buf->len;
	response_buf->len = (uint32_t)totalsize;

	memcpy(resp_p, ptr, bufsize);

	/* NULL-terminate string */
	response_buf->buf[response_buf->len] = '\0';

	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "Current complete retrieved data (len %u): %s\n",
	       response_buf->len, response_buf->buf);

out:
	atomic_bool_set_true(task_complete);
	return;
}

static int acvp_nsurl_http_common(const struct acvp_na_ex *netinfo,
				  const struct acvp_ext_buf *submit_buf,
				  struct acvp_buf *resp_buf,
				  enum acvp_http_type http_type)
{
	const struct acvp_net_ctx *net = netinfo->net;
	const struct acvp_auth_ctx *auth = netinfo->server_auth;
	NSURL *url;
	NSMutableURLRequest *urlRequest;
	NSString *submit;
	ACVPHTTPRequest *http;
	const char *http_type_str;
	char useragent[30];
	long rc = 0;
	int ret;
	unsigned int retries = 0;

	CKNULL_LOG(net, -EINVAL, "Network context missing\n");
	CKNULL_LOG(netinfo->url, -EINVAL, "URL missing\n");
	
	if (!acvp_certs) {
		mutex_lock(&acvp_certs_lock);
		if (!acvp_certs)
			acvp_certs = [[ACVPHTTPCerts alloc]
				      initWithNetinfo:netinfo];
		mutex_unlock(&acvp_certs_lock);
	}
	
	CKNULL_LOG(acvp_certs, -EFAULT, "Certificates not loaded\n");
	
	http = [[ACVPHTTPRequest alloc] initWithCerts:acvp_certs];
	if (http == nil) {
		ret = -ENOMEM;
		goto out;
	}
	
	url = [NSURL URLWithString:[NSString stringWithFormat:@"%s",
				    netinfo->url]];
	urlRequest = [NSMutableURLRequest requestWithURL:url];

	CKINT(acvp_versionstring_short(useragent, sizeof(useragent)));

	if (submit_buf) {
		[urlRequest setValue:@"application/json"
		  forHTTPHeaderField:@"Content-Type"];
		[urlRequest setValue:[NSString stringWithFormat:@"%u",
				      submit_buf->len]
		  forHTTPHeaderField:@"Content-Length"];
		
		submit = [NSString stringWithFormat:@"%s",
			  submit_buf->buf];
	}
        
	if (auth && auth->jwt_token && auth->jwt_token_len) {
		[urlRequest setValue:[NSString stringWithFormat:@"Bearer %s",
				      auth->jwt_token]
		  forHTTPHeaderField:@"Authorization"];
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "HTTP Authentication header: Bearer %s\n",
		       auth->jwt_token);
	}
	
	[urlRequest setValue:[NSString stringWithFormat:@"%s",
			      useragent]
	  forHTTPHeaderField:@"User-Agent"];

	switch (http_type) {
	case acvp_http_get:
		http_type_str = "GET";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP GET operation\n");
		/* Nothing special */
		break;
	case acvp_http_post:
		http_type_str = "POST";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP POST operation\n");
		if (!submit_buf || !submit_buf->buf || !submit_buf->len) {
			logger(LOGGER_WARN, LOGGER_C_CURL, "Nothing to POST\n");
			ret = -EINVAL;
			goto out;
		}

		[urlRequest setHTTPMethod:@"POST"];
		[urlRequest setHTTPBody:
		 [submit dataUsingEncoding:NSUTF8StringEncoding]];
			
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "About to HTTP POST the following data:\n%s\n",
		       submit_buf->buf);
		break;
	case acvp_http_put:
		http_type_str = "PUT";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP PUT operation\n");
		if (!submit_buf || !submit_buf->buf || !submit_buf->len) {
			logger(LOGGER_WARN, LOGGER_C_CURL, "Nothing to PUT\n");
			ret = -EINVAL;
			goto out;
		}

		[urlRequest setHTTPMethod:@"PUT"];
		[urlRequest setHTTPBody:[submit dataUsingEncoding:NSUTF8StringEncoding]];

		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "About to HTTP PUT the following data:\n%s\n",
		       submit_buf->buf);
		break;
	case acvp_http_delete:
		http_type_str = "DELETE";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP DELETE operation\n");
		[urlRequest setHTTPMethod:@"DELETE"];
		break;
	case acvp_http_post_multi:
	case acvp_http_none:
	default:
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unhandled HTTP request option %u\n", http_type);
		ret = -EINVAL;
		goto out;
	}

	/* Perform the HTTP request */
	while (retries < ACVP_CURL_MAX_RETRIES) {
		rc = [http sendRequestFromURL: urlRequest
				  interrupted: &acvp_nsurl_interrupted
				 response_buf: resp_buf
				   completion: ^(struct acvp_buf *response_buf,
						 atomic_bool_t *completed,
						 NSData *data,
						 NSURLResponse * response,
						 NSError *error) {
			acvp_nsurl_write_cb(response_buf, completed, data,
					    response, error);
		}];
		
		if (rc >= 200 && rc < 300) {
			ret = 0;
			break;
		}

		/* Do stop processing if server return a permanent error */
		if (rc >= 400 && rc < 500) {
			logger(LOGGER_VERBOSE, LOGGER_C_CURL,
			       "HTTP permanent error %ld received\n", rc);
			break;
		}

		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "HTTP operation failed with code %ld\n", rc);
		if (rc < 0) {
			ret = (int)rc;
			goto out;
		}

		retries++;
		if (retries < ACVP_CURL_MAX_RETRIES) {
			int ret2;

			/*
			 * Do not reuse the variable ret as it must be left
			 * untouched in case it contains the error from the
			 * HTTP operation.
			 */
			ret2 = sleep_interruptible(10, &acvp_nsurl_interrupted);
			if (ret2 < 0) {
				ret = ret2;
				goto out;
			}
			acvp_free_buf(resp_buf);
		}
	}

	/* Get the HTTP response status code from the server */
	if (rc == 200) {
		ret = 0;
	} else {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unable to HTTP %s data for URL %s\n",
		       http_type_str, url.absoluteString.UTF8String);
		ret = -(int)rc;
	}

out:
	return ret;
}

static int acvp_nsurl_http_post(const struct acvp_na_ex *netinfo,
			       const struct acvp_ext_buf *submit_buf,
			       struct acvp_buf *response_buf)
{
	return acvp_nsurl_http_common(netinfo, submit_buf, response_buf,
				      acvp_http_post);
}

static int acvp_nsurl_http_get(const struct acvp_na_ex *netinfo,
			      struct acvp_buf *response_buf)
{
	return acvp_nsurl_http_common(netinfo, NULL, response_buf,
				      acvp_http_get);
}

static int acvp_nsurl_http_put(const struct acvp_na_ex *netinfo,
			      const struct acvp_ext_buf *submit_buf,
			      struct acvp_buf *response_buf)
{
	return acvp_nsurl_http_common(netinfo, submit_buf, response_buf,
				      acvp_http_put);
}

static int acvp_nsurl_http_delete(const struct acvp_na_ex *netinfo,
				 struct acvp_buf *response_buf)
{
	return acvp_nsurl_http_common(netinfo, NULL, response_buf,
				      acvp_http_delete);
}

static int acvp_nsurl_http_post_multi(const struct acvp_na_ex *netinfo,
				      const struct acvp_ext_buf *submit_buf,
				      struct acvp_buf *resp_buf)
{
	const struct acvp_ext_buf *s_buf;
	const struct acvp_net_ctx *net = netinfo->net;
	const struct acvp_auth_ctx *auth = netinfo->server_auth;
	NSURL *url;
	NSMutableURLRequest *urlRequest;
	ACVPHTTPRequest *http;
	char useragent[30];
	long rc = 0;
	int ret;
	unsigned int retries = 0;
	NSString *postLength;
	NSString *BoundaryConstant = [[NSUUID UUID] UUIDString];
	NSString *contentType = [NSString stringWithFormat:@"multipart/form-data; boundary=%@", BoundaryConstant];
	NSMutableData *body = [NSMutableData data];

	CKNULL_LOG(net, -EINVAL, "Network context missing\n");
	CKNULL_LOG(netinfo->url, -EINVAL, "URL missing\n");
	CKNULL_LOG(submit_buf, -EINVAL, "Submit buffer missing\n");

	if (!acvp_certs) {
		mutex_lock(&acvp_certs_lock);
		if (!acvp_certs)
			acvp_certs = [[ACVPHTTPCerts alloc]
				      initWithNetinfo:netinfo];
		mutex_unlock(&acvp_certs_lock);
	}

	CKNULL_LOG(acvp_certs, -EFAULT, "Certificates not loaded\n");

	http = [[ACVPHTTPRequest alloc] initWithCerts:acvp_certs];
	if (http == nil) {
		ret = -ENOMEM;
		goto out;
	}

	url = [NSURL URLWithString:[NSString stringWithFormat:@"%s",
				    netinfo->url]];
	urlRequest = [NSMutableURLRequest requestWithURL:url];

	if (auth && auth->jwt_token && auth->jwt_token_len) {
		[urlRequest setValue:[NSString stringWithFormat:@"Bearer %s",
				      auth->jwt_token]
		  forHTTPHeaderField:@"Authorization"];
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "HTTP Authentication header: Bearer %s\n",
		       auth->jwt_token);
	}

	CKINT(acvp_versionstring_short(useragent, sizeof(useragent)));

	[urlRequest setValue:[NSString stringWithFormat:@"%s",
			      useragent]
	  forHTTPHeaderField:@"User-Agent"];

	/* Assemble multi-part information */
	[urlRequest setValue:contentType
	  forHTTPHeaderField:@"Content-Type"];

	for (s_buf = submit_buf; s_buf; s_buf = s_buf->next) {
		[body appendData:[[NSString stringWithFormat:@"--%@\r\n",
				   BoundaryConstant] dataUsingEncoding:NSUTF8StringEncoding]];
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "Set mime type %s\n",
		       s_buf->data_type);

		if (s_buf->filename) {
			[body appendData:[[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"%s\"; filename=\"%s\"\r\n\r\n",
					   s_buf->data_type, s_buf->filename]
					  dataUsingEncoding:NSUTF8StringEncoding]];
			logger(LOGGER_DEBUG, LOGGER_C_CURL,
			       "Add file name %s\n", s_buf->filename);
		} else {
			[body appendData:[[NSString stringWithFormat:@"Content-Disposition: form-data; name=\"%s\"\r\n\r\n",
					   s_buf->data_type]
					  dataUsingEncoding:NSUTF8StringEncoding]];
		}

		if (s_buf->buf) {
			logger(LOGGER_DEBUG, LOGGER_C_CURL,
			       "Adding binary data of length %u\n",
			       s_buf->len);
			[body appendData:[NSData dataWithBytes:s_buf->buf
							length:s_buf->len]];
		}

		[body appendData:[[NSString stringWithFormat:@"\r\n"] dataUsingEncoding:NSUTF8StringEncoding]];
	}

	[body appendData:[[NSString stringWithFormat:@"--%@--\r\n",
			   BoundaryConstant]
			  dataUsingEncoding:NSUTF8StringEncoding]];

	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "Performing a multi-form HTTP POST operation\n");

	[urlRequest setHTTPMethod:@"POST"];
	[urlRequest setHTTPBody:body];

	/* Content length */
	postLength = [NSString stringWithFormat:@"%lu", (unsigned long) [body length]];
	[urlRequest setValue:postLength forHTTPHeaderField:@"Content-Length"];

	/* Perform the HTTP request */
	while (retries < ACVP_CURL_MAX_RETRIES) {
		rc = [http sendRequestFromURL: urlRequest
				  interrupted: &acvp_nsurl_interrupted
				 response_buf: resp_buf
				   completion: ^(struct acvp_buf *response_buf,
						 atomic_bool_t *completed,
						 NSData *data,
						 NSURLResponse * response,
						 NSError *error) {
			acvp_nsurl_write_cb(response_buf, completed, data,
					    response, error);
		}];

		if (rc >= 200 && rc < 300) {
			ret = 0;
			break;
		}

		/* Do stop processing if server return a permanent error */
		if (rc >= 400 && rc < 500) {
			logger(LOGGER_VERBOSE, LOGGER_C_CURL,
			       "HTTP permanent error %ld received\n", rc);
			break;
		}

		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "HTTP operation failed with code %ld\n", rc);
		if (rc < 0) {
			ret = (int)rc;
			goto out;
		}

		retries++;
		if (retries < ACVP_CURL_MAX_RETRIES) {
			int ret2;

			/*
			 * Do not reuse the variable ret as it must be left
			 * untouched in case it contains the error from the
			 * HTTP operation.
			 */
			ret2 = sleep_interruptible(10, &acvp_nsurl_interrupted);
			if (ret2 < 0) {
				ret = ret2;
				goto out;
			}
			acvp_free_buf(resp_buf);
		}
	}

	/* Get the HTTP response status code from the server */
	if (rc == 200) {
		ret = 0;
	} else {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unable to HTTP POST data for URL %s\n",
		       url.absoluteString.UTF8String);
		ret = -(int)rc;
	}

out:
	return ret;
}

static struct acvp_netaccess_be acvp_netaccess_nsurl = {
	&acvp_nsurl_http_post,
	&acvp_nsurl_http_post_multi,
	&acvp_nsurl_http_get,
	&acvp_nsurl_http_put,
	&acvp_nsurl_http_delete,
	&acvp_nsurl_interrupt
};

ACVP_DEFINE_CONSTRUCTOR(acvp_nsurl_init)
static void acvp_nsurl_init(void)
{
	acvp_register_na(&acvp_netaccess_nsurl);
}
