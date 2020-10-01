/* ACVP Error code converter
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

#include "acvp_error_handler.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"
#include "ret_checkers.h"

int acvp_error_convert(const struct acvp_buf *response_buf,
		       const int http_ret,
		       enum acvp_error_code *code)
{
	struct json_object *response = NULL, *entry = NULL;
	const char *error_str;
	int ret = 0;

	/* Ensure we have a valid error code in any case */
	*code = ACVP_ERR_NO_ERR;

	/* If we have no error, return successfully */
	if (!http_ret)
		return 0;

	/* HTTP error codes */
	switch (http_ret) {
	case -401:
	case -403:
		logger(LOGGER_VERBOSE, LOGGER_C_CURL,
		       "ACVP server return code: JWT expired\n");
		*code = ACVP_ERR_AUTH_JWT_EXPIRED;
		return 0;
	default:
		break;
	}

	if (!response_buf || !response_buf->buf || !response_buf->len ||
	    !http_ret)
		return http_ret;

	/* Error codes from the ACVP data */

	//TODO: fix after issue #863 is cleared
	logger(LOGGER_VERBOSE, LOGGER_C_CURL,
	       "ACVP server return code: test response received, verdict pending\n");
	*code = ACVP_ERR_RESPONSE_RECEIVED_VERDICT_PENDING;
	goto out;

	CKINT(acvp_req_strip_version(response_buf, &response, &entry));

	if (json_get_string(entry, "error", &error_str))
		goto out;

	logger(LOGGER_ERR, LOGGER_C_ANY,
	       "ACVP error code %s unknown and unhandled\n", error_str);
	ret = http_ret;

out:
	ACVP_JSON_PUT_NULL(response);
	return ret;
}
