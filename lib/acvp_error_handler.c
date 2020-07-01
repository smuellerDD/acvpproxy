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

#include <acvp_error_handler.h>
#include <internal.h>
#include <json_wrapper.h>
#include <request_helper.h>
#include <ret_checkers.h>

#define ACVP_ERR_CODE(name)	{ .error_str = #name, .error_code = name }

struct acvp_error_code_convert {
	const char *error_str;
	enum acvp_error_code error_code;
} acvp_error_code_converter[] = {
	ACVP_ERR_CODE(ACVP_ERR_RESPONSE_RECEIVED_VERDICT_PENDING),
	ACVP_ERR_CODE(ACVP_ERR_RESPONSE_REJECTED)
};

int acvp_error_convert(const struct acvp_buf *response_buf,
		       int http_ret,
		       enum acvp_error_code *code)
{
	struct json_object *response = NULL, *entry = NULL;
	const char *error_str;
	unsigned int i;
	int ret;

	(void)http_ret;

	/* Ensure we have a valid error code in any case */
	*code = ACVP_ERR_NO_ERR;

	if (!response_buf->buf || !response_buf->len)
		return 0;

	//TODO add more return code checks

	//TODO: fix after issue #863 is cleared
	*code = ACVP_ERR_RESPONSE_RECEIVED_VERDICT_PENDING;
	ret = 0;
	goto out;

	CKINT(acvp_req_strip_version(response_buf, &response, &entry));

	if (json_get_string(entry, "error", &error_str))
		goto out;

	for (i = 0; i < ARRAY_SIZE(acvp_error_code_converter); i++) {
		if (acvp_find_match(error_str,
				    acvp_error_code_converter[i].error_str,
				    false)) {
			*code = acvp_error_code_converter[i].error_code;
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "ACVP error code %s converted into internal representation %u\n",
			       error_str,
			       acvp_error_code_converter[i].error_str);
			goto out;
		}
	}

	logger(LOGGER_ERR, LOGGER_C_ANY,
	       "ACVP error code %s unknown and unhandled\n", error_str);
	ret = -EOPNOTSUPP;

out:
	ACVP_JSON_PUT_NULL(response);
	return ret;
}
