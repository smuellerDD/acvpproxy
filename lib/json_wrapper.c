/* Wrapper for JSON-C functions
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

#include <limits.h>
#include <errno.h>

#include "json_wrapper.h"
#include "logger.h"
#include "internal.h"

void json_logger(enum logger_verbosity severity, enum logger_class class,
		 struct json_object *jobj, const char *str)
{
	// JSON_C_TO_STRING_PLAIN
	// JSON_C_TO_STRING_SPACED
	// JSON_C_TO_STRING_PRETTY
	logger(severity, class, "%s: %s\n", str,
	       json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY |
					      JSON_C_TO_STRING_NOSLASHESCAPE));
}

int json_find_key(struct json_object *inobj, const char *name,
		  struct json_object **out, enum json_type type)
{
	if (!json_object_object_get_ex(inobj, name, out)) {
		/*
		 * Use debug level only as optional fields may be searched
		 * for.
		 */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "JSON field %s does not exist\n", name);
		return -EINVAL;
	}

	if (!json_object_is_type(*out, type)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "JSON data type %s does not match expected type %s for field %s\n",
		       json_type_to_name(json_object_get_type(*out)),
		       json_type_to_name(type), name);
		return -EINVAL;
	}

	return 0;
}

int json_get_string(struct json_object *obj, const char *name,
		    const char **outbuf)
{
	struct json_object *o = NULL;
	const char *string;
	int ret = json_find_key(obj, name, &o, json_type_string);

	if (ret)
		return ret;

	string = json_object_get_string(o);

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Found string data %s with value %s\n", name,
	       string);

	*outbuf = string;

	return 0;
}

int json_get_uint(struct json_object *obj, const char *name, uint32_t *integer)
{
	struct json_object *o = NULL;
	int32_t tmp;
	int ret = json_find_key(obj, name, &o, json_type_int);

	if (ret)
		return ret;

	tmp = json_object_get_int(o);
	if (tmp >= INT_MAX)
		return -EINVAL;

	*integer = (uint32_t)tmp;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Found integer %s with value %u\n", name, *integer);

	return 0;
}

int json_get_bool(struct json_object *obj, const char *name, bool *bool)
{
	struct json_object *o = NULL;
	json_bool tmp;
	int ret = json_find_key(obj, name, &o, json_type_boolean);

	if (ret)
		return ret;

	tmp = json_object_get_boolean(o);

	*bool = !!tmp;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Found boolean %s with value %u\n", name, *bool);

	return 0;
}

int acvp_req_add_version(struct json_object *array)
{
	struct json_object *entry;
	int ret;

	entry = json_object_new_object();
	CKNULL(entry, ENOMEM);
	CKINT(json_object_object_add(entry, "acvVersion",
				     json_object_new_string(ACVP_VERSION)));
	CKINT(json_object_array_add(array, entry));

	return 0;

out:
	ACVP_JSON_PUT_NULL(entry);
	return ret;
}

int acvp_req_strip_version(const uint8_t *buf,
			   struct json_object **full_json,
			   struct json_object **parsed)
{
	struct json_object *resp;
	uint32_t i;
	int ret = 0;

	if (!buf)
		return 0;

	resp = json_tokener_parse((const char*)buf);
	CKNULL(resp, -EINVAL);
	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, resp,
		    "Parsed ACVP response\n");

	*full_json = resp;

	*parsed = NULL;

	/* Parse response */
	if (json_object_get_type(resp) == json_type_array) {
		for (i = 0; i < (uint32_t)json_object_array_length(resp); i++) {
			struct json_object *found =
					json_object_array_get_idx(resp, i);

			/* discard version information */
			if (json_object_object_get_ex(found, "acvVersion",
						      NULL))
				continue;

			*parsed = found;
			break;
		}
		if (!*parsed) {
			json_logger(LOGGER_ERR, LOGGER_C_ANY, resp,
				    "No data found in ACVP server response");
			ret = -EINVAL;
			goto out;
		}
	} else {
		*parsed = resp;
	}

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, *parsed,
		    "Stripped ACVP response");

out:
	return ret;
}
