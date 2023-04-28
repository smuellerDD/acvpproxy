/* JSON request generator for SP800-108 KDF
 *
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "definition.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "request_helper.h"

int acvp_req_set_prereq_kdf_108(const struct def_algo_kdf_108 *kdf_108,
				const struct acvp_test_deps *deps,
				struct json_object *entry, bool publish)
{
	int ret;

	CKINT(json_object_object_add(entry, "algorithm",
				     json_object_new_string("KDF")));

	CKINT(acvp_req_gen_prereq(kdf_108->prereqvals,
				  kdf_108->prereqvals_num, deps, entry,
				  publish));

out:
	return ret;
}

int acvp_list_algo_kdf_108(const struct def_algo_kdf_108 *kdf_108,
			   struct acvp_list_ciphers **new)
{
	struct acvp_list_ciphers *tmp = NULL;
	int ret;

	tmp = calloc(1, sizeof(struct acvp_list_ciphers));
	CKNULL(tmp, -ENOMEM);
	*new = tmp;

	CKINT(acvp_duplicate(&tmp->cipher_name, "KDF"));
	CKINT(acvp_duplicate(&tmp->cipher_mode, "SP800-108"));
	CKINT(acvp_req_cipher_to_stringarray(kdf_108->macalg,
					     ACVP_CIPHERTYPE_MAC,
					     &tmp->cipher_aux));
	tmp->prereqs = kdf_108->prereqvals;
	tmp->prereq_num = kdf_108->prereqvals_num;

	tmp->keylen[0] = DEF_ALG_ZERO_VALUE;

out:
	return ret;
}

int acvp_req_set_algo_kdf_108_details(const struct def_algo_kdf_108 *kdf_108,
				      struct json_object *entry)
{
	struct json_object *array;
	int ret;
	bool found = false;

	switch (kdf_108->kdf_108_type) {
	case DEF_ALG_KDF_108_COUNTER:
		CKINT(json_object_object_add(entry, "kdfMode",
					     json_object_new_string("counter")));
		break;
	case DEF_ALG_KDF_108_FEEDBACK:
		CKINT(json_object_object_add(entry, "kdfMode",
			json_object_new_string("feedback")));
		break;
	case DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION:
		CKINT(json_object_object_add(entry, "kdfMode",
			json_object_new_string("double pipeline iteration")));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "SP800-108 KDF: Unknown kdf_108_type\n");
		ret = -EINVAL;
		goto out;
	}

	CKINT(acvp_req_cipher_to_array(entry, kdf_108->macalg,
				       ACVP_CIPHERTYPE_MAC, "macMode"));

	CKINT(acvp_req_algo_int_array(entry, kdf_108->supported_lengths,
				      "supportedLengths"));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "fixedDataOrder", array));
	if (kdf_108->fixed_data_order & DEF_ALG_KDF_108_COUNTER_ORDER_NONE) {
		if (kdf_108->kdf_108_type == DEF_ALG_KDF_108_COUNTER) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "SP800-108 KDF: DEF_ALG_KDF_108_COUNTER_ORDER_NONE not allowed for counter KDF mode\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_array_add(array,
					    json_object_new_string("none")));
		found = true;
	}
	if (kdf_108->fixed_data_order &
	    DEF_ALG_KDF_108_COUNTER_ORDER_AFTER_FIXED_DATA) {
		CKINT(json_object_array_add(array,
			json_object_new_string("after fixed data")));
		found = true;
	}
	if (kdf_108->fixed_data_order &
	    DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_FIXED_DATA) {
		CKINT(json_object_array_add(array,
			json_object_new_string("before fixed data")));
		found = true;
	}
	if (kdf_108->fixed_data_order &
	    DEF_ALG_KDF_108_COUNTER_ORDER_MIDDLE_FIXED_DATA) {
		if (kdf_108->kdf_108_type == DEF_ALG_KDF_108_FEEDBACK ||
		    kdf_108->kdf_108_type ==
		     DEF_ALG_KDF_108_DOUBLE_PIPELINE_ITERATION) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "SP800-108 KDF: DEF_ALG_KDF_108_COUNTER_ORDER_MIDDLE_FIXED_DATA not allowed for feedback and double pipeline iteration KDF mode\n");
			ret = -EINVAL;
			goto out;
		}

		CKINT(json_object_array_add(array,
			json_object_new_string("middle fixed data")));
		found = true;
	}
	if (kdf_108->fixed_data_order &
	    DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_ITERATOR) {
		if (kdf_108->kdf_108_type == DEF_ALG_KDF_108_COUNTER) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "SP800-108 KDF: DEF_ALG_KDF_108_COUNTER_ORDER_BEFORE_ITERATOR not allowed for counter KDF mode\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_array_add(array,
			json_object_new_string("before iterator")));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL, "fixed_data_order contains wrong data\n");

	found = false;
	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "counterLength", array));
	if (kdf_108->counter_lengths & DEF_ALG_KDF_108_COUNTER_LENGTH_0) {
		if (kdf_108->kdf_108_type == DEF_ALG_KDF_108_COUNTER) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "SP800-108 KDF: DEF_ALG_KDF_108_COUNTER_LENGTH_0 not allowed for counter KDF mode\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT(json_object_array_add(array, json_object_new_int(0)));
		found = true;
	}
	if (kdf_108->counter_lengths & DEF_ALG_KDF_108_COUNTER_LENGTH_8) {
		CKINT(json_object_array_add(array, json_object_new_int(8)));
		found = true;
	}
	if (kdf_108->counter_lengths & DEF_ALG_KDF_108_COUNTER_LENGTH_16) {
		CKINT(json_object_array_add(array, json_object_new_int(16)));
		found = true;
	}
	if (kdf_108->counter_lengths & DEF_ALG_KDF_108_COUNTER_LENGTH_24) {
		CKINT(json_object_array_add(array, json_object_new_int(24)));
		found = true;
	}
	if (kdf_108->counter_lengths & DEF_ALG_KDF_108_COUNTER_LENGTH_32) {
		CKINT(json_object_array_add(array, json_object_new_int(32)));
		found = true;
	}
	CKNULL_LOG(found, -EINVAL,
		   "SP800-108 KDF: counter_lengths contains wrong data\n");

	CKINT(json_object_object_add(entry, "supportsEmptyIv",
			json_object_new_boolean(kdf_108->supports_empty_iv)));
	CKINT(json_object_object_add(entry, "requiresEmptyIv",
			json_object_new_boolean(kdf_108->requires_empty_iv)));

out:
	return ret;
}

/*
 * Generate algorithm entry for SP800-108 KDF
 */
int acvp_req_set_algo_kdf_108(const struct def_algo_kdf_108 *kdf_108,
			      struct json_object *entry)
{
	struct json_object *array, *tmp;
	int ret;

	CKINT(acvp_req_add_revision(entry, "1.0"));

	CKINT(acvp_req_set_prereq_kdf_108(kdf_108, NULL, entry, false));

	array = json_object_new_array();
	CKNULL(array, -ENOMEM);
	CKINT(json_object_object_add(entry, "capabilities", array));

	tmp = json_object_new_object();
	CKNULL(tmp, -ENOMEM);
	CKINT(json_object_array_add(array, tmp));

	CKINT(acvp_req_set_algo_kdf_108_details(kdf_108, tmp));

out:
	return ret;
}
