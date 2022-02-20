/*
 * Copyright (C) 2019 - 2022, Stephan Mueller <smueller@chronox.de>
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

#define _XOPEN_SOURCE 600
#include <time.h>
#include <string.h>

#include "internal.h"
#include "json_wrapper.h"

int acvp_str_match(const char *exp, const char *found, const uint32_t id)
{
	size_t len;

	if (!exp && !found)
		return 0;

	/*
	 * It is possible to have a JSON NULL value - on one side. In this
	 * case, we have a mismatch.
	 */
	if ((!exp && found) || (exp && !found))
		return -ENOENT;

	len = strlen(exp);

	if (len != strlen(found) || strncmp(exp, found, len)) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Mismatch for ID %u (expected: %s, found: %s)\n", id,
		       exp, found);
		return -ENOENT;
	}

	return 0;
}

int acvp_get_verdict_json(const struct acvp_buf *verdict_buf,
			  enum acvp_test_verdict *verdict_stat)
{
	struct json_object *verdict_full = NULL, *verdict, *resobject;
	int ret;
	const char *result;
	bool test_passed;

	CKINT_LOG(acvp_req_strip_version(verdict_buf, &verdict_full, &verdict),
		  "JSON parser cannot parse verdict data\n");

	ret = json_get_bool(verdict, "passed", &test_passed);
	if (!ret) {
		if (test_passed)
			*verdict_stat = acvp_verdict_pass;
		else
			*verdict_stat = acvp_verdict_fail;
		goto out;
	}

	/*
	 * Our verdict may contain a status information in case of an error
	 * and thus a different JSON structure.
	 */
	if (json_find_key(verdict, "results", &resobject, json_type_object))
		resobject = verdict;

	ret = json_get_string(resobject, "disposition", &result);
	if (ret < 0) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "JSON parser cannot find verdict data\n");
		*verdict_stat = acvp_verdict_unknown;
		ret = 0;
		goto out;
	}

	if (!strncmp(result, "passed", 6)) {
		*verdict_stat = acvp_verdict_pass;
	} else if (!strncmp(result, "unreceived", 10)) {
		*verdict_stat = acvp_verdict_unreceived;
	} else {
		*verdict_stat = acvp_verdict_fail;
	}

out:
	ACVP_JSON_PUT_NULL(verdict_full);
	return ret;
}

int acvp_get_testsession_expiry(const struct acvp_buf *meta_buf, char *date,
				size_t datelen)
{
	struct json_object *meta_full = NULL, *meta;
	const char *str;
	int ret;

	CKINT_LOG(acvp_req_strip_version(meta_buf, &meta_full, &meta),
		  "JSON parser cannot parse verdict data\n");

	CKINT(json_get_string(meta, "expiresOn", &str));
	snprintf(date, datelen, "%s", str);

out:
	ACVP_JSON_PUT_NULL(meta_full);
	return ret;
}

int acvp_get_testsession_expiry_epoch(const struct acvp_buf *meta_buf,
				      time_t *epoch)
{
	struct tm time;
	char date[128];
	int ret;

	CKINT(acvp_get_testsession_expiry(meta_buf, date, sizeof(date)));

	memset(&time, 0, sizeof(time));
	strptime(date, "%Y-%Om-%dT%H:%M:%S", &time);

	*epoch = mktime(&time);

out:
	return ret;
}

int acvp_get_algoinfo_json(const struct acvp_buf *buf,
			   struct acvp_test_verdict_status *verdict)
{
	struct json_object *algo_full = NULL, *algo;
	int ret;
	const char *tmp;

	CKINT_LOG(acvp_req_strip_version(buf, &algo_full, &algo),
		  "JSON parser cannot parse verdict data\n");

	CKINT(json_get_string(algo, "algorithm", &tmp));
	CKINT(acvp_duplicate(&verdict->cipher_name, tmp));

	ret = json_get_string(algo, "mode", &tmp);
	if (!ret) {
		CKINT(acvp_duplicate(&verdict->cipher_mode, tmp));
	} else {
		ret = 0;
	}

out:
	ACVP_JSON_PUT_NULL(algo_full);
	return ret;
}
