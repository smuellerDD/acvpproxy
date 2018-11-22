/* Helper code with common functions
 *
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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
#include "internal.h"
#include "logger.h"

static int _acvp_req_algo_int_array_always(struct json_object *entry,
					   const int vals[],
					   unsigned int numvals,
					   const char *key)
{
	struct json_object *tmp_array;
	int ret = -EINVAL;

	unsigned int i;

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);
	for (i = 0; i < numvals; i++) {
		if (!vals[i])
			break;
		CKINT(json_object_array_add(tmp_array,
			json_object_new_int((vals[i] == DEF_ALG_ZERO_VALUE) ?
					     0 : vals[i])));
	}
	json_object_object_add(entry, key, tmp_array);

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

int acvp_req_gen_range(struct json_object *entry,
		       const struct def_algo_range *range, const char *key)
{
	struct json_object *tmp = json_object_new_object();
	struct json_object *range_obj = json_object_new_object();
	int ret = 0;

	CKNULL(tmp, -ENOMEM);
	CKNULL(range_obj, -ENOMEM);

	json_object_object_add(tmp, "min", json_object_new_int(range->min));
	json_object_object_add(tmp, "max", json_object_new_int(range->max));
	json_object_object_add(tmp, "increment",
			       json_object_new_int(range->increment));
	json_object_object_add(range_obj, "myRange", tmp);
	json_object_object_add(entry, key, range_obj);

	return 0;

out:
	if (tmp)
		json_object_put(tmp);
	if (range_obj)
		json_object_put(range_obj);
	return ret;
}

int acvp_req_gen_domain(struct json_object *entry,
			const struct def_algo_range *range, const char *key)
{
	struct json_object *tmp = json_object_new_object();
	struct json_object *tmp_array = json_object_new_array();
	int ret = 0;

	CKNULL(tmp, -ENOMEM);
	CKNULL(tmp_array, -ENOMEM);

	CKINT(json_object_object_add(tmp, "min",
				     json_object_new_int(range->min)));
	CKINT(json_object_object_add(tmp, "max",
				     json_object_new_int(range->max)));
	CKINT(json_object_object_add(tmp, "increment",
			       json_object_new_int(range->increment)));
	CKINT(json_object_array_add(tmp_array, tmp));
	CKINT(json_object_object_add(entry, key, tmp_array));

	return 0;

out:
	if (tmp)
		json_object_put(tmp);
	if (tmp_array)
		json_object_put(tmp_array);
	return ret;
}

int acvp_req_gen_prereq(const struct def_algo_prereqs *prereqs,
			unsigned int num, struct json_object *entry)
{
	struct json_object *tmp_array = NULL, *tmp = NULL;
	unsigned int i;
	int ret = 0;

	if (!prereqs || !num)
		return 0;

	tmp_array = json_object_new_array();
	CKNULL(tmp_array, -ENOMEM);

	for (i = 0; i < num; i++) {
		if (!prereqs || !prereqs->algorithm || !prereqs->valvalue)
			break;

		tmp = json_object_new_object();
		CKNULL(tmp, -ENOMEM);
		json_object_object_add(tmp, "algorithm",
			json_object_new_string(prereqs->algorithm));
		json_object_object_add(tmp, "valValue",
			json_object_new_string(prereqs->valvalue));
		CKINT(json_object_array_add(tmp_array, tmp));

		prereqs++;
	}
	json_object_object_add(entry, "prereqVals", tmp_array);

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
	json_object_object_add(entry, "keyLen", tmp_array);
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
		json_object_object_add(entry, "keyingOption", tmp_array);
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

int acvp_extend_string(char *string, unsigned int stringmaxlen,
		       const char *fmt, ...)
{
	va_list args;
	char part[FILENAME_MAX];
	unsigned int stringlen = strlen(string);

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

int acvp_create_url(const struct acvp_net_ctx *net, const char *path,
		    char *url, uint32_t urllen)
{
	int ret = 0;

	CKNULL_LOG(path, -EINVAL, "No path for URL creation provided\n");
	CKNULL_LOG(url, -EINVAL,
		   "No destination buffer for URL creation provided\n");

	snprintf(url, urllen, "https://%s:%u/%s/%s",
		 net->server_name, net->server_port, NIST_VAL_CTX,
		 path);
	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "ACVP URL: %s\n", url);

out:
	return ret;
}

int acvp_get_trailing_number(const char *string, uint32_t *number)
{
	size_t len = strlen(string);
	unsigned int numsep = 0;
	const char *string_p = string;
	const char *saveptr = NULL;

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
