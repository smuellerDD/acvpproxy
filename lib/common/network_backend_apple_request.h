/*
 *
 * Copyright (C) 2020 - 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef network_backend_apple_request_h
#define network_backend_apple_request_h

#import <Foundation/Foundation.h>

#import "network_backend_apple_certs.h"

#include "buffer.h"
#include "atomic_bool.h"

@interface ACVPHTTPRequest : NSObject <NSURLSessionDelegate>

- (long)sendRequestFromURL:(NSMutableURLRequest *)urlRequest
	       interrupted:(atomic_bool_t *)interrupted
	      response_buf:(struct acvp_buf *)response_buf
		completion:(void (^)(struct acvp_buf *, atomic_bool_t *,
				     NSData *, NSURLResponse *,
				     NSError *))completion;

- (id)initWithCerts:(ACVPHTTPCerts *)initCerts;

@end

#endif /* network_backend_apple_request_h */
