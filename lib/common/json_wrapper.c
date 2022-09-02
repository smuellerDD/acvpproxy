/* Wrapper for JSON-C functions
 *
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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
#include <string.h>

#include "binhexbin.h"
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
	       json_object_to_json_string_ext(
		       jobj, JSON_C_TO_STRING_PRETTY |
				     JSON_C_TO_STRING_NOSLASHESCAPE));
}

int json_find_key(const struct json_object *inobj, const char *name,
		  struct json_object **out, enum json_type type)
{
	if (!json_object_object_get_ex(inobj, name, out)) {
		/*
		 * Use debug level only as optional fields may be searched
		 * for.
		 */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "JSON field %s does not exist\n", name);
		return -ENOENT;
	}

	if (!json_object_is_type(*out, type)) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "JSON data type %s does not match expected type %s for field %s\n",
		       json_type_to_name(json_object_get_type(*out)),
		       json_type_to_name(type), name);
		return -EINVAL;
	}

	return 0;
}

int json_get_string(const struct json_object *obj, const char *name,
		    const char **outbuf)
{
	struct json_object *o = NULL;
	const char *string;
	int ret = json_find_key(obj, name, &o, json_type_string);

	*outbuf = NULL;
	if (ret)
		return ret;

	string = json_object_get_string(o);

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Found string data %s with value %s\n", name, string);

	*outbuf = string;

	return 0;
}

int json_get_string_zero_to_null(const struct json_object *obj,
				 const char *name, const char **outbuf)
{
	int ret;

	CKINT(json_get_string(obj, name, outbuf));

	/*
	 * The ACVP server will discard zero length strings. This implies that
	 * suddenly we have a mismatch between our database and the server.
	 * Thus, replicate the ACVP server behavior here, too.
	 */
	if (strlen(*outbuf) == 0)
		*outbuf = NULL;
out:
	return ret;
}

int json_get_uint(const struct json_object *obj, const char *name,
		  uint32_t *integer)
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

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Found integer %s with value %u\n",
	       name, *integer);

	return 0;
}

int json_get_uint64(struct json_object *obj, const char *name,
		    uint64_t *integer)
{
	struct json_object *o = NULL;
	int64_t tmp;
	int ret = json_find_key(obj, name, &o, json_type_int);

	if (ret)
		return ret;

	tmp = json_object_get_int64(o);

	*integer = (uint64_t)tmp;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Found integer %s with value %" PRIu64 "\n", name, *integer);

	return 0;
}

int json_get_double(struct json_object *obj, const char *name, double *val)
{
	struct json_object *o = NULL;
	int ret = json_find_key(obj, name, &o, json_type_double);

	if (ret)
		ret = json_find_key(obj, name, &o, json_type_int);

	if (ret)
		return ret;

	*val = json_object_get_double(o);

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Found integer %s with value %f\n",
	       name, *val);

	return 0;
}

int json_get_bool(struct json_object *obj, const char *name, bool *val)
{
	struct json_object *o = NULL;
	json_bool tmp;
	int ret = json_find_key(obj, name, &o, json_type_boolean);

	if (ret)
		return ret;

	tmp = json_object_get_boolean(o);

	*val = !!tmp;

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Found boolean %s with value %u\n",
	       name, *val);

	return 0;
}

int acvp_req_add_version(struct json_object *array)
{
	const struct acvp_net_proto *proto;
	struct json_object *entry = NULL;
	int ret;

	CKINT(acvp_get_proto(&proto));

	entry = json_object_new_object();
	CKNULL(entry, ENOMEM);
	CKINT(json_object_object_add(
		entry, proto->proto_version_keyword,
		json_object_new_string(proto->proto_version)));
	CKINT(json_object_array_add(array, entry));

	return 0;

out:
	ACVP_JSON_PUT_NULL(entry);
	return ret;
}

int json_split_version(struct json_object *full_json,
		       struct json_object **inobj,
		       struct json_object **versionobj)
{
	const struct acvp_net_proto *proto;
	int ret = 0;
	uint32_t i;

	if (!full_json)
		return -EINVAL;

	*inobj = NULL;
	*versionobj = NULL;

	CKINT(acvp_get_proto(&proto));

	/* Parse response */
	if (json_object_is_type(full_json, json_type_array)) {
		/*
		 * Split the response array into version object and
		 * data object.
		 *
		 * [{
		 *	"version", "1.0"
		 * }, {
		 * 	... some data ...
		 * }]
		 */
		for (i = 0; i < (uint32_t)json_object_array_length(full_json);
		     i++) {
			struct json_object *found =
				json_object_array_get_idx(full_json, i);

			/* discard version information */
			if (json_object_object_get_ex(
				    found, proto->proto_version_keyword,
				    NULL)) {
				*versionobj = found;
			} else {
				*inobj = found;
			}
		}
		if (!*inobj || !*versionobj) {
			json_logger(LOGGER_WARN, LOGGER_C_ANY, full_json,
				    "No data found in ACVP server response");
			ret = -EINVAL;
			goto out;
		}

		json_logger(LOGGER_DEBUG, LOGGER_C_ANY, *inobj, "ACVP vector");
		json_logger(LOGGER_DEBUG, LOGGER_C_ANY, *versionobj,
			    "ACVP version");

		if (!json_object_is_type(*inobj, json_type_object) ||
		    !json_object_is_type(*versionobj, json_type_object)) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "JSON data are not expected ACVP objects\n");
			ret = EINVAL;
			goto out;
		}
	} else if (json_object_is_type(full_json, json_type_object)) {
		/*
		 * If we receive an object, we return it directly.
		 * This may happen with error messages.
		 *
		 * {
		 *	"version": "1.0",
		 *	"error": "some error message"
		 * }
		 */
		*inobj = full_json;
	} else {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "JSON data is not an expected ACVP object\n");
		ret = EINVAL;
		goto out;
	}

out:
	return ret;
}

int acvp_req_strip_version(const struct acvp_buf *buf,
			   struct json_object **full_json,
			   struct json_object **parsed)
{
	struct json_object *resp, *version;
	struct json_tokener *tok;
	int ret = 0;

	if (!buf || !buf->buf || !buf->len)
		return 0;

	if (buf->len > INT32_MAX)
		return -EOVERFLOW;

	tok = json_tokener_new();
	CKNULL(tok, -ENOMEM);

	resp = json_tokener_parse_ex(tok, (const char *)buf->buf,
				     (int)buf->len);
	json_tokener_free(tok);

	CKNULL_LOG(resp, -EINVAL, "JSON tokener cannot parse ASCII data\n");
	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, resp,
		    "Parsed ACVP response\n");

	*full_json = resp;
	*parsed = NULL;

	return json_split_version(resp, parsed, &version);

out:
	return ret;
}

int json_read_data(const char *filename, struct json_object **inobj)
{
	struct json_object *o = json_object_from_file(filename);
	int ret;

	if (!o) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "Cannot parse input file %s\n",
		       filename);
		return -EFAULT;
	}

	if (!json_object_is_type(o, json_type_array)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "JSON input data is not expected ACVP array\n");
		ret = -EINVAL;
		goto out;
	}

	*inobj = o;

	return 0;

out:
	json_object_put(o);
	return ret;
}

int json_add_bin2hex(struct json_object *dst, const char *key,
		     const struct acvp_buf *buf)
{
	char *hex;
	uint32_t hexlen;
	int ret;

	if (buf->len == 0) {
		json_object_object_add(dst, key, json_object_new_string(""));
		return 0;
	}

	ret = bin2hex_alloc(buf->buf, buf->len, &hex, &hexlen);
	if (ret)
		return ret;

	ret = json_object_object_add(dst, key, json_object_new_string(hex));
	free(hex);

	return ret;
}
