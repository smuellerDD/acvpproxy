/* Helper code with common functions
 *
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <string.h>
#include <stdarg.h>

#include "acvpproxy.h"
#include "build_bug_on.h"
#include "internal.h"
#include "logger.h"

static inline int acvp_req_check_zero(const int val)
{
	return ((val == DEF_ALG_ZERO_VALUE) ? 0 : val);
}

int acvp_req_valid_range_one(unsigned int min, unsigned int max,
			     unsigned int step, int supported_length)
{
	if (supported_length < (int)min ||
	    supported_length > (int)max ||
	    supported_length % (int)step)
		return -EINVAL;
	return 0;
}

int acvp_req_valid_range(unsigned int min, unsigned int max, unsigned int step,
			 const int supported_lengths[])
{
	unsigned int i;

	/* Check with range domain. */
	if (supported_lengths[0]  & DEF_ALG_RANGE_TYPE) {
		int range_min = supported_lengths[0] & ~DEF_ALG_RANGE_TYPE;
		int range_max = supported_lengths[1];
		int range_step = supported_lengths[2];

		if (range_min == DEF_ALG_ZERO_VALUE)
			range_min = 0;

		if (range_min >= (int)min && range_max <= (int)max &&
		    !(range_step % (int)step) &&
		    !(range_min % (int)step) && !(range_max % (int)step))
			return 0;

		return -EINVAL;
	}

	/* Check with finite set of integers. */
	for (i = 0; i < DEF_ALG_MAX_INT; i++) {
		int length = supported_lengths[i];
		int ret;

		if (!length)
			break;

		if (length == DEF_ALG_ZERO_VALUE)
			length = 0;

		ret = acvp_req_valid_range_one(min, max, step, length);
		if (ret)
			return ret;
	}

	return 0;
}

int acvp_req_in_range(unsigned int val, const int supported_lengths[])
{
	unsigned int i;

	/* Check with range domain. */
	if (supported_lengths[0]  & DEF_ALG_RANGE_TYPE) {
		int min = supported_lengths[0] & ~DEF_ALG_RANGE_TYPE;
		int max = supported_lengths[1];
		int inc = supported_lengths[2];

		if (min <= (int)val &&
		    max >= (int)val &&
		    !((int)val % inc))
			return 0;

		return -EINVAL;
	}

	/* Check with finite set of integers. */
	for (i = 0; i < DEF_ALG_MAX_INT; i++) {
		if (!supported_lengths[i])
			break;
		if (supported_lengths[i] == (int)val)
			return 0;
	}

	return -EINVAL;
}

int acvp_req_algo_domain(struct json_object *entry,
			 int min, int max, int inc,
			 const char *key)
{
	struct json_object *lenarray, *len;
	int ret;

	/* The range domain requires at least 3 fields */
	BUILD_BUG_ON(DEF_ALG_MAX_INT < 3);

	/* We are required for SHAKE to use a min/max/inc domain */
	lenarray = json_object_new_array();
	CKNULL(lenarray, -ENOMEM);
	CKINT(json_object_object_add(entry, key, lenarray));
	len = json_object_new_object();
	CKNULL(len, -ENOMEM);
	CKINT(json_object_array_add(lenarray, len));
	CKINT(json_object_object_add(len, "min",
				json_object_new_int(acvp_req_check_zero(min))));
	CKINT(json_object_object_add(len, "max",
				json_object_new_int(acvp_req_check_zero(max))));
	CKINT(json_object_object_add(len, "increment",
				json_object_new_int(acvp_req_check_zero(inc))));

out:
	return ret;
}

static int _acvp_req_algo_int_array_always(struct json_object *entry,
					   const int vals[],
					   unsigned int numvals,
					   const char *key)
{
	struct json_object *tmp_array;
	int ret = -EINVAL;
	unsigned int i;

	/*
	 * Create a range domain.
	 */
	if (vals[0]  & DEF_ALG_RANGE_TYPE) {
		return acvp_req_algo_domain(entry,
					    (vals[0] & ~DEF_ALG_RANGE_TYPE),
					    vals[1], vals[2], key);
	}

	/*
	 * Create a domain consisting of finite set of integers.
	 */
	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	for (i = 0; i < numvals; i++) {
		if (!vals[i])
			break;
		CKINT(json_object_array_add(tmp_array,
			json_object_new_int(acvp_req_check_zero(vals[i]))));
	}
	CKINT(json_object_object_add(entry, key, tmp_array));

	return 0;

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}

int acvp_req_algo_int_array_always(struct json_object *entry,
				   const int vals[], const char *key)
{
	return _acvp_req_algo_int_array_always(entry, vals,
					       DEF_ALG_MAX_INT, key);
}

int acvp_req_algo_int_array_len(struct json_object *entry, const int vals[],
				unsigned int numvals, const char *key)
{
	if (!vals[0])
		return 0;

	return _acvp_req_algo_int_array_always(entry, vals, numvals, key);
}

int acvp_req_algo_int_array(struct json_object *entry, const int vals[],
			    const char *key)
{
	if (!vals[0])
		return 0;

	return _acvp_req_algo_int_array_always(entry, vals,
					       DEF_ALG_MAX_INT, key);
}

int acvp_req_cipher_to_name(cipher_t cipher, cipher_t cipher_type_mask,
			    const char **name)
{
	unsigned int i;
	cipher_t typemask = cipher_type_mask ? cipher_type_mask :
					       ACVP_CIPHERTYPE;

	for (i = 0; i < ARRAY_SIZE(cipher_def_map); i++) {
		if ((cipher & typemask) &
		     (cipher_def_map[i].cipher & typemask) &&
		    (cipher & ACVP_CIPHERDEF) &
		     (cipher_def_map[i].cipher & ACVP_CIPHERDEF)) {
			*name = cipher_def_map[i].acvp_name;

			return 0;
		}
	}

	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
	       "No ciphers found for cipher mask (ciphers %lu, mask %lu)\n",
	       cipher, cipher_type_mask);

	return -EINVAL;
}

int acvp_req_cipher_to_string(struct json_object *entry, cipher_t cipher,
			      cipher_t cipher_type_mask, const char *key)
{
	const char *name;
	int ret;

	CKINT(acvp_req_cipher_to_name(cipher, cipher_type_mask, &name));
	json_object_object_add(entry, key, json_object_new_string(name));

out:
	return ret;
}

int acvp_req_cipher_to_array(struct json_object *entry, cipher_t cipher,
			     cipher_t cipher_type_mask, const char *key)
{
	struct json_object *array;
	cipher_t typemask = cipher_type_mask ? cipher_type_mask :
					       ACVP_CIPHERTYPE;
	unsigned int i;
	bool found = false;

	array = json_object_new_array();
	if (!array)
		return -ENOMEM;
	json_object_object_add(entry, key, array);

	for (i = 0; i < ARRAY_SIZE(cipher_def_map); i++) {
		if ((cipher & typemask) &
		     ((cipher_def_map[i].cipher) & typemask) &&
		    (cipher & ACVP_CIPHERDEF) &
		     ((cipher_def_map[i].cipher) & ACVP_CIPHERDEF)) {
			json_object_array_add(array,
				json_object_new_string(
					cipher_def_map[i].acvp_name));

			found = true;
		}
	}


	return found ? 0 : -EINVAL;
}

/* Return true when a match is found, otherwise false */
bool acvp_find_match(const char *searchstr, const char *defstr,
		     bool fuzzy_search)
{
	/* If no searchstring is provided, we match */
	if (!searchstr)
		return true;
	if (!defstr)
		return true;

	if (fuzzy_search) {
		/* We perform a substring search */
		logger(LOGGER_DEBUG2, LOGGER_C_ANY,
		       "Fuzzy search for %s in string %s\n", searchstr, defstr);

		if (strstr(defstr, searchstr))
			return true;
		else
			return false;
	} else {
		size_t defstr_len = strlen(defstr);
		size_t searchstr_len = strlen(searchstr);

		/* Exact search */
		logger(LOGGER_DEBUG2, LOGGER_C_ANY,
		       "Exact search for %s in string %s\n", searchstr, defstr);

		if (defstr_len != searchstr_len)
			return false;

		if (strncmp(searchstr, defstr, defstr_len))
			return false;
		else
			return true;
	}
}

int acvp_req_gen_prereq(const struct def_algo_prereqs *prereqs,
			unsigned int num,
			const struct acvp_test_deps *deps,
			struct json_object *entry,
			bool publish)
{
	const struct acvp_test_deps *curr_dep;
	struct json_object *tmp_array = NULL, *tmp = NULL;
	unsigned int i;
	int ret = 0;

	if (!prereqs || !num)
		return 0;

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);

	for (i = 0; i < num; i++) {
		const char *value;

		if (!prereqs || !prereqs->algorithm || !prereqs->valvalue)
			break;

		value = prereqs->valvalue;

		/* Set certificate number from dependencies */
		for (curr_dep = deps;
		     curr_dep != NULL;
		     curr_dep = curr_dep->next) {
			if (acvp_find_match(curr_dep->dep_cipher,
					    prereqs->algorithm, false)) {
				value = curr_dep->dep_cert;
				break;
			}
		}

		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		CKINT(json_object_object_add(tmp, "algorithm",
				json_object_new_string(prereqs->algorithm)));
		CKINT(json_object_object_add(tmp, publish ? "validationId" :
							    "valValue",
				json_object_new_string(value)));
		CKINT(json_object_array_add(tmp_array, tmp));

		prereqs++;
	}
	json_object_object_add(entry, publish ? "prerequisites" : "prereqVals",
			       tmp_array);

out:
	return ret;
}

int acvp_req_sym_keylen(struct json_object *entry, unsigned int keyflags)
{
	struct json_object *tmp_array = json_object_new_array();
	int ret = 0;

	CKNULL(tmp_array, -ENOMEM);
	if (keyflags & DEF_ALG_SYM_KEYLEN_128)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_int(128)));
	if (keyflags & DEF_ALG_SYM_KEYLEN_168)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_int(168)));
	if (keyflags & DEF_ALG_SYM_KEYLEN_192)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_int(192)));
	if (keyflags & DEF_ALG_SYM_KEYLEN_256)
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_int(256)));
	CKINT(json_object_object_add(entry, "keyLen", tmp_array));
	tmp_array = NULL;

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}

int acvp_req_tdes_keyopt(struct json_object *entry, cipher_t algorithm)
{
	struct json_object *tmp_array = NULL;
	int ret = 0;

	/* Mandate Triple-DES keying option 3 with all three keys independent */
	if (algorithm & ACVP_TDESMASK || algorithm & ACVP_CMAC_TDES) {
		tmp_array = json_object_new_array();
		CKNULL(tmp_array, -ENOMEM);
		CKINT(json_object_array_add(tmp_array,
					    json_object_new_int(1)));
		CKINT(json_object_object_add(entry, "keyingOption", tmp_array));
		tmp_array = NULL;
	}

out:
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}

int acvp_duplicate_string(char **dst, const char *src)
{
	if (*dst)
		free(*dst);
	if (src) {
		*dst = strdup(src);
		if (!(*dst)) {
			logger(LOGGER_ERR, LOGGER_C_ANY, "Out of memory\n");
			return -ENOMEM;
		}
	} else {
		*dst = NULL;
	}

	return 0;
}

int acvp_extend_string(char *string, size_t stringmaxlen,
		       const char *fmt, ...)
{
	va_list args;
	char part[FILENAME_MAX];
	size_t stringlen = strlen(string);

	va_start(args, fmt);
	vsnprintf(part, sizeof(part), fmt, args);
	va_end(args);

	snprintf(string + stringlen,
		 stringmaxlen - stringlen - 1, "%s", part);

	return 0;
}

int acvp_create_urlpath(const char *path, char *url, uint32_t urllen)
{
	int ret = 0;

	CKNULL_LOG(path, -EINVAL, "No path for URL creation provided\n");
	CKNULL_LOG(url, -EINVAL,
		   "No destination buffer for URL creation provided\n");

	snprintf(url, urllen, "/%s/%s", NIST_VAL_CTX, path);
	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "ACVP URL path: %s\n", url);

out:
	return ret;
}

int acvp_create_url(const char *path, char *url, uint32_t urllen)
{
	const struct acvp_net_ctx *net;
	int ret = 0;

	CKNULL_LOG(path, -EINVAL, "No path for URL creation provided\n");
	CKNULL_LOG(url, -EINVAL,
		   "No destination buffer for URL creation provided\n");

	CKINT(acvp_get_net(&net));

	snprintf(url, urllen, "https://%s:%u/%s/%s",
		 net->server_name, net->server_port, NIST_VAL_CTX, path);
	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "ACVP URL: %s\n", url);

out:
	return ret;
}

int acvp_append_urloptions(const char *options, char *url, uint32_t urllen)
{
	int ret = 0;

	CKNULL_LOG(options, -EINVAL,
		   "No HTTP options for URL provided\n");
	CKNULL_LOG(url, -EINVAL,
		   "No destination buffer for URL creation provided\n");

	/*
	 * HTTP options are separated from the URL using the question mark.
	 * We allow the caller to already specify options, such as query
	 * parameters where we already have such question mark. In this case
	 * we only separate the search limits using the ampersand from
	 * the other options.
	 */
	if (strstr(url, "?")) {
		CKINT(acvp_extend_string(url, urllen, "%s%s", "&", options));
	} else {
		CKINT(acvp_extend_string(url, urllen, "%s%s", "?", options));
	}

	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "ACVP URL with options: %s\n",
	       url);

out:
	return ret;
}

int acvp_replace_urloptions(const char *options, char *url, uint32_t urllen)
{
	int ret = 0;
	char *url_p = url;

	CKNULL_LOG(options, -EINVAL,
		   "No HTTP options for URL provided\n");
	CKNULL_LOG(url, -EINVAL,
		   "No destination buffer for URL creation provided\n");

	url_p = strstr(url, "?");
	if (url_p) {
		snprintf(url_p, (size_t)(urllen - (url - url_p)),
			 "%s", options);
	} else {
		CKINT(acvp_extend_string(url, urllen, "%s", options));
	}

	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "ACVP URL with options: %s\n",
	       url);

out:
	return ret;
}

int acvp_get_trailing_number(const char *string, uint32_t *number)
{
	size_t len;
	unsigned int numsep = 0;
	const char *string_p = string;
	const char *saveptr = NULL;

	if (!string) {
		*number = (uint32_t)-1;
		return 0;
	}

	len = strlen(string);

	/* Finding the pointer of the last slash */
	while (len) {
		/* search for slash */
		if (*string_p == 47) {
			saveptr = string_p;
			numsep++;

			if (numsep >= 10) {
				logger(LOGGER_WARN, LOGGER_C_ANY,
				       "more than 10 pathname components found in string %s\n",
				       string);
				return -EINVAL;
			}
		}

		string_p++;
		len--;
	}

	/* tailing character is a slash */
	if (saveptr == string_p) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Trailing character of string %s is a slash\n", string);
		return -EINVAL;
	}


	/* Converting the string behind the last slash */
	if (saveptr) {
		unsigned long val;

		/* Jump behind the slash */
		saveptr++;

		logger(LOGGER_DEBUG, LOGGER_C_ANY, "Converting %s\n", saveptr);
		val = strtoul(saveptr, NULL, 10);
		if (val >= UINT_MAX)
			return -ERANGE;

		*number = (uint32_t)val;

		return 0;
	}

	logger(LOGGER_ERR, LOGGER_C_ANY, "Number not found in string %s\n",
	       string);
	return -EINVAL;
}

int acvp_req_add_revision(struct json_object *entry, const char *str)
{
	return json_object_object_add(entry, "revision",
				      json_object_new_string(str));
}
