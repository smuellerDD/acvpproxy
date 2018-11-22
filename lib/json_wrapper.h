/*
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

#ifndef _JSON_WRAPPER_H
#define _JSON_WRAPPER_H

#include <stdint.h>
#include <json-c/json.h>

#include "bool.h"
#include "logger.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Log the JSON object.
 */
void json_logger(enum logger_verbosity severity, enum logger_class class,
		 struct json_object *jobj, const char *str);

/*
 * Find arbitrary key in toplevel hierarchy and check that value is of
 * given type. If key is found and of expected type, return reference to
 * object.
 */
int json_find_key(struct json_object *inobj, const char *name,
		  struct json_object **out, enum json_type type);

/*
 * Get the string representation of the value found at the given key
 */
int json_get_string(struct json_object *obj, const char *name,
		    const char **outbuf);

/*
 * Get the uint32_t representation of an integer referenced with the given key.
 */
int json_get_uint(struct json_object *obj, const char *name, uint32_t *integer);

/*
 * Get the boolean representation of an integer referenced with the given key.
 */
int json_get_bool(struct json_object *obj, const char *name, bool *bool);

/*
 * Get the uint32_t representation of an integer referenced with the given key.
 */
int json_get_uint64(struct json_object *obj, const char *name,
		    uint64_t *integer);

/*
 * Add version information to a request.
 */
int acvp_req_add_version(struct json_object *array);

/**
 * Parse ACVP server response and retrieve array entry that contains the
 * real data (discard the version number)
 *
 * Typical server response:
 *
 * [
 *   { "acvVersion": "0.3" },
 *   { "vsId": 1437,
 *     ....
 *   }
 * ]
 *
 * @buf: [in] buffer containing JSON data from ACVP server
 * @full_json: [out] JSON object containing fully parsed ACVP response
 * @parsed: [out] JSON object that contains the real data
 *
 * Note: Caller must release full_json. The parsed value is only a pointer into
 * full_json.
 */
int acvp_req_strip_version(const uint8_t *buf,
			   struct json_object **full_json,
			   struct json_object **parsed);

#ifdef __cplusplus
}
#endif

#endif /* _JSON_WRAPPER_H */
