/* Reading and writing of ESVP status information for re-entrant support
 *
 * Copyright (C) 2021 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "base64.h"
#include "esvp_internal.h"
#include "json_wrapper.h"

static int esvp_write_filehash(struct json_object *entry,
			       const struct acvp_buf *data_hash,
			       const char *keyword)
{
	char *base64_buf = NULL;
	size_t base64_len;
	int ret;

	if (!data_hash->buf)
		return 0;

	CKINT(base64_encode(data_hash->buf, data_hash->len, &base64_buf,
			    &base64_len));

	CKINT(json_object_object_add(entry, keyword,
				     json_object_new_string(base64_buf)));

out:
	free(base64_buf);
	return ret;
}

static int esvp_read_filehash(struct json_object *entry,
			      struct acvp_buf *data_hash,
			      const char *keyword)
{
	const char *base64_buf;
	uint8_t *base64_data = NULL;
	size_t base64_len;
	int ret;

	CKINT(json_get_string(entry, keyword, &base64_buf));

	if (data_hash->buf) {
		CKINT(base64_decode(base64_buf, strlen(base64_buf),
				    &base64_data, &base64_len));
		if ((base64_len != data_hash->len) ||
		    memcmp(base64_data, data_hash->buf, base64_len)) {
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "File hash mismatch for file %s\n", keyword);
			ret = -ENOENT;
		}
	} else {
		CKINT(base64_decode(base64_buf, strlen(base64_buf),
				    &data_hash->buf, &base64_len));
		if (base64_len > UINT32_MAX) {
			ret = -ERANGE;
		} else {
			data_hash->len = (uint32_t)base64_len;
			ret = -ENOENT;
		}
	}

out:
	free(base64_data);
	return ret;
}

static int esvp_get_es(struct esvp_es_def **es_out,
		       const struct acvp_testid_ctx *testid_ctx)
{
	/* TODO constify */
	struct esvp_es_def *es;
	int ret = 0;

	CKNULL(testid_ctx, -EINVAL);

	es = testid_ctx->es_def;

	if (!es) {
		const struct definition *def = testid_ctx->def;

		CKNULL(def, -EFAULT);

		/*
		 * TODO This assignment requires single threaded operation -
		 * see esvp_init_testid_ctx
		 */
		es = def->es;
		CKNULL(es, -EFAULT);
	}

	*es_out = es;

out:
	return ret;
}

/***************************************************************************
 * ESVP status handling
 ***************************************************************************/
int esvp_read_status(const struct acvp_testid_ctx *testid_ctx,
		     struct json_object *status)
{
	struct esvp_es_def *es;
	struct esvp_cc_def *cc;
	struct esvp_sd_def *sd = NULL;
	struct acvp_auth_ctx *auth;
	struct json_object *array;
	unsigned int seq_no = 1, i;
	const char *str;
	int ret;

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Parsing status of ESVP\n");

	CKINT(esvp_get_es(&es, testid_ctx));

	/* Allow those values to not exist - then they are marked as false */
	json_get_string(status, "eaRuntimeResultsStatus", &str);
	//TODO: remove call if es is testid-local
	ACVP_PTR_FREE_NULL(es->ea_runtime_results_status);
	CKINT(acvp_duplicate(&es->ea_runtime_results_status, str));
	json_get_string(status, "eaRestartResultsStatus", &str);
	//TODO: remove call if es is testid-local
	ACVP_PTR_FREE_NULL(es->ea_restart_results_status);
	CKINT(acvp_duplicate(&es->ea_restart_results_status, str));

	CKINT(json_get_uint(status, "rawNoiseBitsId", &es->raw_noise_id));
	CKINT(json_get_bool(status, "rawNoiseBitsSubmitted",
			    &es->raw_noise_submitted));

	CKINT(json_get_uint(status, "restartTestBitsId", &es->restart_id));
	CKINT(json_get_bool(status, "restartTestBitsSubmitted",
			    &es->restart_submitted));

	/* Get access token */
	CKINT(json_get_string(status, "eaAccessToken", &str));

	/*
	 * This call is only allowed because threading is disaled considering
	 * that testid_ctx->es_def is shared between multiple testid_ctx.
	 */
	acvp_release_acvp_auth_ctx(es->es_auth);
	ACVP_PTR_FREE_NULL(es->es_auth);

	/* Store access token in ctx */
	CKINT(acvp_init_acvp_auth_ctx(&es->es_auth));
	auth = es->es_auth;
	CKINT_LOG(acvp_set_authtoken_temp(auth, str),
		  "Cannot set the new JWT token\n");
	CKINT(json_get_uint64(status, "eaAccessTokenGenerated",
			      (uint64_t *)&auth->jwt_token_generated));

	/* Duplicate the authtoken for the testid context */
	CKINT(acvp_copy_auth(testid_ctx->server_auth, auth));

	for (cc = es->cc; cc; cc = cc->next, seq_no++) {
		struct json_object *stat_cc;
		char ref[40];
		/*
		 * Only process non-vetted and non-bijective conditioning
		 * components.
		 */
		if (cc->vetted || cc->bijective)
			continue;

		snprintf(ref, sizeof(ref), "conditioningComponent%u", seq_no);
		CKINT(json_find_key(status, ref, &stat_cc, json_type_object));
		CKINT(json_get_uint(stat_cc, "conditionedBitsId", &cc->cc_id));
		CKINT(json_get_bool(stat_cc, "conditionedBitsSubmitted",
				    &cc->output_submitted));

		/* Read hash */
		ret = esvp_read_filehash(stat_cc, &cc->data_hash, "fileHash");
		/* Hash does not match current hash -> (re-)submit file */
		if (ret == -ENOENT)
			cc->output_submitted = false;
		else if (ret)
			goto out;
	}

	ret = json_find_key(status, "supportingDocumentation", &array,
			    json_type_array);
	if (ret) {
		ret = 0;
		goto out;
	}

	for (i = 0; i < json_object_array_length(array); i++) {
		struct json_object *filenames;
		struct json_object *sd_entry =
			json_object_array_get_idx(array, i);

		sd = calloc(1, sizeof(struct esvp_sd_def));
		CKNULL(sd, -ENOMEM);

		/* Get access token */
		CKINT(json_get_string(sd_entry, "accessToken", &str));
		/* Store access token in ctx */
		CKINT(acvp_init_acvp_auth_ctx(&sd->sd_auth));
		auth = sd->sd_auth;
		CKINT_LOG(acvp_set_authtoken_temp(auth, str),
			  "Cannot set the new JWT token\n");

		CKINT(json_get_uint64(sd_entry, "accessTokenGenerated",
				      (uint64_t *)&auth->jwt_token_generated));

		CKINT(json_get_uint(sd_entry, "sdId", &sd->sd_id));

		/* Data was submitted */
		sd->submit = true;

		/* Old status handling */
		ret = json_get_string(sd_entry, "filename", &str);
		if (!ret) {
			struct esvp_sd_file_def *file = calloc(1,
							       sizeof(*file));

			CKNULL(file, -ENOMEM);
			sd->file = file;

			CKINT(acvp_duplicate(&file->filename, str));
			CKINT(json_get_bool(sd_entry, "submitted",
					    &file->submitted));
		}

		/* New status handling */
		ret = json_find_key(sd_entry, "filenames", &filenames,
				    json_type_array);
		if (!ret) {
			unsigned int j;

			for (j = 0;
			     j < json_object_array_length(filenames);
			     j++) {
				struct json_object *file_entry =
					json_object_array_get_idx(filenames, j);
				struct esvp_sd_file_def *file;

				CKNULL(file_entry, -EINVAL);

				file = calloc(1, sizeof(*file));
				CKNULL(file, -ENOMEM);
				if (!sd->file) {
					sd->file = file;
				} else {
					struct esvp_sd_file_def *f = sd->file;

					while (f->next)
						f = f->next;

					f->next = file;
				}

				CKINT(json_get_string(file_entry, "filename",
						      &str));
				CKINT(acvp_duplicate(&file->filename, str));
				CKINT(json_get_bool(file_entry, "submitted",
						    &file->submitted));

				/* Allow this being optional */
				json_get_uint(file_entry, "documentType",
					      &sd->document_type);

				ret = esvp_read_filehash(file_entry,
							 &file->data_hash,
							 "fileHash");
				/*
				 * Hash does not match current hash ->
				 * (re-)submit file
				 */
				if (ret == -ENOENT)
					file->submitted = false;
				else if (ret)
					goto out;
			}
		}
		ret = 0;

		/*
		 * Append the new conditioning component entry at the end of
		 * the list because the order matters.
		 */
		if (es->sd) {
			struct esvp_sd_def *iter_sd = es->sd;

			while (iter_sd) {
				/* Avoid duplicat entries */
				if (iter_sd->sd_id == sd->sd_id) {
					/*
					 * As we have submitted it,
					 * mark it so.
					 */
					iter_sd->submit = true;
					esvp_def_sd_free(sd);
					break;
				}
				if (!iter_sd->next) {
					iter_sd->next = sd;
					break;
				}
				iter_sd = iter_sd->next;
			}
		} else {
			es->sd = sd;
		}
	}

out:
	if (ret)
		esvp_def_sd_free(sd);

	return ret;
}

int esvp_build_sd(const struct acvp_testid_ctx *testid_ctx,
		  struct json_object *sd_array, bool write_extended)
{
	struct esvp_es_def *es;
	const struct esvp_sd_def *sd;
	int ret = 0;

	CKINT(esvp_get_es(&es, testid_ctx));

	if (!es->sd)
		return 0;

	for (sd = es->sd; sd; sd = sd->next) {
		struct json_object *sd_data;
		struct acvp_auth_ctx *auth;

		/* If requested, do not submit the file */
		if (!sd->submit)
			continue;

		auth = sd->sd_auth;
		sd_data = json_object_new_object();
		CKNULL(sd_data, -ENOMEM);
		CKINT(json_object_array_add(sd_array, sd_data));
		CKINT(json_object_object_add(
			sd_data, "sdId", json_object_new_int((int)sd->sd_id)));
		CKINT(json_object_object_add(
			sd_data, "accessToken",
			json_object_new_string(auth->jwt_token)));
		if (write_extended) {
			struct esvp_sd_file_def *file = sd->file;
			struct json_object *file_array;

			CKINT(json_object_object_add(
				sd_data, "accessTokenGenerated",
				json_object_new_int64(
					auth->jwt_token_generated)));

			file_array = json_object_new_array();
			CKINT(json_object_object_add(sd_data, "filenames",
						     file_array));

			while (file) {
				struct json_object *file_data;

				file_data = json_object_new_object();
				CKNULL(file_data, -ENOMEM);
				CKINT(json_object_array_add(file_array,
							    file_data));

				CKINT(json_object_object_add(
						file_data, "filename",
						json_object_new_string(
							file->filename)));
				CKINT(json_object_object_add(
						file_data, "submitted",
						json_object_new_boolean(
							file->submitted)));
				CKINT(json_object_object_add(
						file_data, "documentType",
						json_object_new_int(
							(int)sd->document_type)));
				CKINT(esvp_write_filehash(file_data,
							  &file->data_hash,
							  "fileHash"));

				file = file->next;
			}
		}
	}

out:
	return ret;
}

int esvp_write_status(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	struct esvp_es_def *es = testid_ctx->es_def;
	const struct esvp_cc_def *cc;
	struct json_object *sd_array, *stat = NULL;
	struct acvp_buf stat_buf;
	struct acvp_auth_ctx *auth;
	const char *stat_str;
	unsigned int seq_no = 1;
	int ret;

	stat = json_object_new_object();
	CKNULL(stat, -ENOMEM);

	CKINT(esvp_get_es(&es, testid_ctx));

	if (es->ea_runtime_results_status) {
		CKINT(json_object_object_add(
		      stat, "eaRuntimeResultsStatus",
		      json_object_new_string(es->ea_runtime_results_status)));
	}
	if (es->ea_restart_results_status) {
		CKINT(json_object_object_add(
		      stat, "eaRestartResultsStatus",
		      json_object_new_string(es->ea_restart_results_status)));
	}

	CKINT(json_object_object_add(
		stat, "rawNoiseBitsId",
		json_object_new_int((int)es->raw_noise_id)));
	CKINT(json_object_object_add(
		stat, "rawNoiseBitsSubmitted",
		json_object_new_boolean(es->raw_noise_submitted)));
	CKINT(json_object_object_add(stat, "restartTestBitsId",
				     json_object_new_int((int)es->restart_id)));
	CKINT(json_object_object_add(
		stat, "restartTestBitsSubmitted",
		json_object_new_boolean(es->restart_submitted)));

	auth = es->es_auth;
	if (auth) {
		CKINT(json_object_object_add(
			stat, "eaAccessToken",
			json_object_new_string(auth->jwt_token)));
		CKINT(json_object_object_add(
			stat, "eaAccessTokenGenerated",
			json_object_new_int64(auth->jwt_token_generated)));
	}

	for (cc = es->cc; cc; cc = cc->next, seq_no++) {
		struct json_object *stat_cc;
		char ref[40];
		/*
		 * Only process non-vetted and non-bijective conditioning
		 * components.
		 */
		if (cc->vetted || cc->bijective)
			continue;

		stat_cc = json_object_new_object();
		CKNULL(stat_cc, -ENOMEM);

		snprintf(ref, sizeof(ref), "conditioningComponent%u", seq_no);

		CKINT(json_object_object_add(stat, ref, stat_cc));
		CKINT(json_object_object_add(
			stat_cc, "conditionedBitsId",
			json_object_new_int((int)cc->cc_id)));
		CKINT(json_object_object_add(
			stat_cc, "conditionedBitsSubmitted",
			json_object_new_boolean(cc->output_submitted)));
		CKINT(esvp_write_filehash(stat_cc, &cc->data_hash,
					  "fileHash"));
	}

	sd_array = json_object_new_array();
	CKNULL(sd_array, -ENOMEM);
	CKINT(json_object_object_add(stat, "supportingDocumentation",
				     sd_array));
	CKINT(esvp_build_sd(testid_ctx, sd_array, true));

	stat_str = json_object_to_json_string_ext(
		stat, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(stat_str, -ENOMEM,
		   "JSON object conversion into string failed\n");

	stat_buf.buf = (uint8_t *)stat_str;
	stat_buf.len = (uint32_t)strlen(stat_str);

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(
		testid_ctx, datastore->esvp_statusfile, true, &stat_buf));

out:
	ACVP_JSON_PUT_NULL(stat);

	return ret;
}
