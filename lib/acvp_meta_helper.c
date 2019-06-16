/*
 * Copyright (C) 2019, Stephan Mueller <smueller@chronox.de>
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

#include <string.h>

#include "internal.h"
#include "json_wrapper.h"

int acvp_str_match(const char *exp, const char *found, uint32_t id)
{
	if (strncmp(exp, found, strlen(exp))) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Mismatch for ID %u (expected: %s, found: %s)\n",
		       id, exp, found);
		return -ENOENT;
	}

	return 0;
}

int acvp_get_verdict_json(const struct acvp_buf *verdict_buf,
			  bool *test_passed)
{
	struct json_object *verdict_full = NULL, *verdict;
	int ret;
	const char *result;

	CKINT_LOG(acvp_req_strip_version(verdict_buf->buf, &verdict_full,
					 &verdict),
		  "JSON parser cannot parse verdict data\n");

	ret = json_get_bool(verdict, "passed", test_passed);
	if (!ret)
		goto out;

	CKINT(json_get_string(verdict, "disposition", &result));

	if (ret < 0)
		  logger(LOGGER_WARN, LOGGER_C_ANY,
			 "JSON parser cannot find verdict data\n");

	if (strncmp(result, "passed", 6)) {
		*test_passed = false;
	} else {
		*test_passed = true;
	}

out:
	ACVP_JSON_PUT_NULL(verdict_full);
	return ret;
}
