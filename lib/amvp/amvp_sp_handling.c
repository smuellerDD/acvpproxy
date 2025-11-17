/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "amvp_internal.h"
#include "base64.h"
#include "internal.h"
#include "request_helper.h"
#include "sleep.h"

/******************************************************************************
 * SP PDF generation and gathering
 ******************************************************************************/

static int amvp_sp_handle_get_pdf_response(
	const struct acvp_vsid_ctx *certreq_ctx, struct acvp_buf *response)
{
	uint8_t *filedata = NULL, *digest = NULL;
	size_t filedatalen, digestlen;
	const char *str;
	struct json_object *resp = NULL, *data = NULL;
	int ret;

	/* Strip the version array entry and get the SP data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));
	CKINT(json_get_string(data, "status", &str));

	if (!strncasecmp(str, "success", 7)) {
		HASH_CTX_ON_STACK(ctx);
		ACVP_BUFFER_INIT(filebuf);
		char spfile[100];
		uint8_t digest_compare[AMVP_SP_HASH_SIZE];

		logger_status(LOGGER_C_ANY, "Security Policy downloaded\n");

		/* Get the PDF which is base64 encoded and decode it */
		CKINT(json_get_string(data, "content", &str));
		CKINT(base64_decode(str, strlen(str), &filedata, &filedatalen));
		if (filedatalen > UINT32_MAX) {
			logger(LOGGER_ERR, LOGGER_C_ANY, "Retrieved file too large\n");
			ret = -EOVERFLOW;
			goto out;
		}

		/* Get the SHA-256 message digest of the PDF */
		CKINT(json_get_string(data, "digest", &str));
		CKINT(base64_decode(str, strlen(str), &digest, &digestlen));
		if (digestlen != AMVP_SP_HASH_SIZE) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Retrieved digest data is not of the expected length for SHA-256 (length: %zu)\n",
			       digestlen);
			ret = -EINVAL;
			goto out;
		}

		/* Create the message digest of the downloaded SP PDF */
		sha256->init(ctx);
		sha256->update(ctx, filedata, filedatalen);
		sha256->final(ctx, digest_compare);

		/* Check if hash(downloaded PDF) == downloaded hash */
		if (memcmp(digest_compare, digest, sizeof(digest_compare))) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Security Policy integrity verification failed - Document unexpectedly altered! File is stored nonetheless for manual recovery, but do not trust it!\n");
		} else {
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "Integrity of Security Policy document verified\n");
		}

		/* Now store the PDF */
		filebuf.buf = filedata;
		filebuf.len = (uint32_t)filedatalen;

		/* Generate file name of Security Policy */
		snprintf(spfile, sizeof(spfile), "%"PRIu64"%s",
			 certreq_ctx->vsid, AMVP_DS_SP_FILENAME);

		CKINT(ds->acvp_datastore_write_vsid(certreq_ctx, spfile,
						    false, &filebuf));
		logger_status(LOGGER_C_ANY,
			      "Security Policy PDF file stored in certificate request %"PRIu64" database directory\n",
			      certreq_ctx->vsid);

	} else if (!strncasecmp(str, "pending", 7)) {
		logger_status(LOGGER_C_ANY,
			      "Security Policy pending - retry later\n");
		ret = 0;
		goto out;
	} else {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Unexpected status while requesting the Security Policy: %s\n",
		       str);

		ret = -EINVAL;
	}

out:
	if (filedata)
		free(filedata);
	if (digest)
		free(digest);
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

static int amvp_sp_add_logo(const struct acvp_vsid_ctx *certreq_ctx,
				 struct json_object *sp_head)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct definition *def = module_ctx->def;
	const struct amvp_def *amvp = def->amvp;
	struct stat statbuf;
	ACVP_BUFFER_INIT(logo);
	char *logo_base64 = NULL;
	size_t logo_base64_len;
	int ret, fd = -1;

	//TODO: remove function?
	return 0;

	CKNULL(amvp->logo_file, 0);

	if (stat(amvp->logo_file, &statbuf)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
			"CMVP SP logo not found at %s\n",
			amvp->logo_file);
		return 0;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Reading SP logo file %s\n",
	       amvp->logo_file);

	fd = open(amvp->logo_file, O_RDONLY);
	if (fd == -1) {
		ret = -errno;

		logger(LOGGER_ERR, LOGGER_C_ANY, "Failed to open file %s: %d\n",
		       amvp->logo_file, ret);
		goto out;
	}

	logo.buf = mmap(NULL, (size_t)statbuf.st_size, PROT_READ, MAP_SHARED,
			fd, 0);
	if (logo.buf == MAP_FAILED) {
		logger(LOGGER_WARN, LOGGER_C_DS_FILE,
		       "Cannot mmap file %s\n", amvp->logo_file);
		ret = -ENOMEM;
		goto out;
	}

	logo.len = (uint32_t)statbuf.st_size;
	CKINT(base64_encode(logo.buf, logo.len, &logo_base64,
			    &logo_base64_len));
	CKINT(json_object_object_add(sp_head, "logo",
				     json_object_new_string(logo_base64)));

out:
	if (logo_base64)
		free(logo_base64);
	if (logo.buf)
		munmap(logo.buf, (size_t)statbuf.st_size);
	if (fd >= 0)
		close(fd);
	return ret;
}

/*
 * PUT /amv/v1/certRequests/<id>/securityPolicy
 *
 * Trigger the generation of the PDF - note, this now locks in the SP sections
 */
static int amvp_sp_generate_pdf(const struct acvp_vsid_ctx *certreq_ctx,
				const char *url)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	struct amvp_state *state = module_ctx->amvp_state;
	const char *json_request;
	struct json_object *request = NULL;
	ACVP_EXT_BUFFER_INIT(request_buf);
	ACVP_BUFFER_INIT(response);
	int ret, ret2;

	request = json_object_new_object();
	CKNULL(request, ENOMEM);
	CKINT(acvp_req_add_version(request));

	CKINT(amvp_sp_add_logo(certreq_ctx, request));

	json_request = json_object_to_json_string_ext(
		request,
		JSON_C_TO_STRING_PLAIN |
		JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	request_buf.buf = (uint8_t *)json_request;
	request_buf.len = (uint32_t)strlen(json_request);

	ret2 = acvp_net_op(module_ctx, url, &request_buf, &response,
			acvp_http_put);
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	CKINT(_amvp_certrequest_status(certreq_ctx, &response,
				       amvp_certrequest_status_show_status));

	/* Implement the waiting */
#define AMVP_GET_DATAFILE_INFO_SLEEPTIME 30
	while (state->sp_state ==
	       AMVP_REQUEST_STATE_PENDING_PROCESSING_GENERATION) {
		/* Wait the requested amount of seconds */
		logger_status(LOGGER_C_ANY,
			"AMVP server needs more time for PDF generation - sleeping for %u seconds for certificate request %"PRIu64" again\n",
			AMVP_GET_DATAFILE_INFO_SLEEPTIME,
			certreq_ctx->vsid);

		CKINT(sleep_interruptible(AMVP_GET_DATAFILE_INFO_SLEEPTIME,
					  &acvp_op_interrupted));

		/* Get the submission status of the SP */
		CKINT(amvp_certrequest_status(
			certreq_ctx, amvp_certrequest_status_show_none));
	}

	if (state->sp_state != AMVP_REQUEST_STATE_COMPLETED) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
			"AMVP was not successful in generating PDF, status %u\n",
			state->sp_state);
		ret = -ENODATA;
		goto out;
	}

out:
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response);
	return ret;
}

/*
 * GET /amv/v1/certRequests/<id>/securityPolicy
 */
int amvp_sp_get_pdf(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct amvp_state *state = module_ctx->amvp_state;
	struct json_object *request = NULL;
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;

	/* Get the submission status of the SP */
	CKINT(amvp_certrequest_status(certreq_ctx,
				      amvp_certrequest_status_show_none));

	if (state->sp_state < AMVP_REQUEST_STATE_PENDING_GENERATION) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Security policy data not yet uploaded - upload it with amvp-proxy --vsid %"PRIu64"\n", certreq_ctx->vsid);
		ret = -EAGAIN;
		goto out;
	}

	if (state->sp_state ==
	    AMVP_REQUEST_STATE_PENDING_PROCESSING_SUBMISSION) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Security policy generation ongoing - wait\n");
		ret = -EAGAIN;
		goto out;
	}

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_SECURITY_POLICY));

	/* PUT operation only needed if we are still pending */
	if (state->sp_state == AMVP_REQUEST_STATE_PENDING_GENERATION) {
		CKINT(amvp_sp_generate_pdf(certreq_ctx, url));
	}

	/* GET operation */
	ret2 = acvp_net_op(module_ctx, url, NULL, &response, acvp_http_get);
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_sp_handle_get_pdf_response(certreq_ctx, &response));

out:
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response);
	return ret;
}

/******************************************************************************
 * SP status processing
 ******************************************************************************/

int amvp_sp_status(const struct acvp_vsid_ctx *certreq_ctx,
		   struct json_object *data)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	struct amvp_state *state = module_ctx->amvp_state;
	ACVP_BUFFER_INIT(stat);
	struct json_object *sp;
	const char *str;
	size_t i;
	int ret;

	/* Get the expected evidence information */
	ret = json_find_key(data, "missingSecurityPolicySection", &sp,
			    json_type_array);
	if (ret) {
		if (ret == -ENOENT)
			ret = 0;
		goto out;
	}
	for (i = 0; i < json_object_array_length(sp); i++) {
		struct json_object *entry = json_object_array_get_idx(sp, i);
		uint32_t section = (uint32_t)json_object_get_int(entry);

		if (section > AMVP_SP_LAST_CHAPTER) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown Security Policy section %u\n", section);
			continue;
		}

		/* Server did not receive data, so wipe the hash */
		if (state->sp_chapter_hash[section]) {
			free(state->sp_chapter_hash[section]);
			state->sp_chapter_hash[section] = NULL;
		}

		logger_status(LOGGER_C_ANY,
			      "SP section %u not yet uploaded or received by NIST server\n",
			      section + 1);
	}

	str = json_object_to_json_string_ext(
		sp, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(str, -ENOMEM,
		   "JSON object conversion into string failed\n");

	stat.buf = (uint8_t *)str;
	stat.len = (uint32_t)strlen(str);

	CKINT(acvp_store_file(module_ctx, &stat, 1, "sp_status.json"));

out:
	return ret;
}

/******************************************************************************
 * SP data uploading
 ******************************************************************************/

/*
 * POST /amvp/v1/certRequests/<id>/securityPolicy/template
 *
 * Send the following form-data
 *
 * | Key | Type | Value |
 * |-----|-------|-------|
 * | amvVersion | string | "0.1" |
 * | documentTemplate | file | {SP Template File} |
 */
static int amvp_sp_send_template(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct definition *def = module_ctx->def;
	const struct amvp_def *amvp = def->amvp;
	struct amvp_state *state = module_ctx->amvp_state;
	ACVP_EXT_BUFFER_INIT(filedata);
	ACVP_EXT_BUFFER_INIT(versiondata);
	ACVP_BUFFER_INIT(response);
	struct stat statbuf;
	int ret, ret2, fd = -1;
	uint8_t hash[AMVP_SP_HASH_SIZE];
	char url[ACVP_NET_URL_MAXLEN];
	HASH_CTX_ON_STACK(ctx);

	versiondata.data_type = "amvVersion";
	versiondata.buf = (uint8_t *)"0.1";
	versiondata.len = 3;
	versiondata.next = &filedata;

	if (stat(amvp->sp_template_file, &statbuf)) {
		int errsv = errno;

		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Accessing file %s failed (stat error code %d)\n",
		       amvp->sp_template_file, errsv);
		return -errsv;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "File %s is not a regular file\n",
		       amvp->sp_template_file);
		return -EINVAL;
	}

	fd = open(amvp->sp_template_file, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;

		logger(LOGGER_WARN, LOGGER_C_DS_FILE,
		       "Cannot open file %s (%d)\n", amvp->sp_template_file, ret);
		goto out;
	}

	filedata.buf = mmap(NULL, (size_t)statbuf.st_size, PROT_READ,
			    MAP_SHARED, fd, 0);
	if (filedata.buf == MAP_FAILED) {
		logger(LOGGER_WARN, LOGGER_C_DS_FILE, "Cannot mmap file %s\n",
		       amvp->sp_template_file);
		ret = -ENOMEM;
		goto out;
	}

	sha256->init(ctx);
	sha256->update(ctx, filedata.buf, filedata.len);
	sha256->final(ctx, hash);

	if (state->sp_template_hash &&
	    !memcmp(state->sp_template_hash, hash, AMVP_SP_HASH_SIZE)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Skipping SP template that was already received by the server\n");
		ret = 0;
		goto out;
	}

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_SECURITY_POLICY));
	CKINT(acvp_extend_string(url, sizeof(url), "/template"));

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Posting file %s\n",
	       amvp->sp_template_file);
	filedata.len = (uint32_t)statbuf.st_size;
	filedata.data_type = "documentTemplate";
	filedata.filename = basename(amvp->sp_template_file);
	filedata.next = NULL;

	logger_status(LOGGER_C_ANY, "Submitting file %s\n",
		      amvp->sp_template_file);

	/* Refresh all auth tokens */
	if (acvp_login_need_refresh(module_ctx)) {
		CKINT(acvp_login_refresh(module_ctx));
	}

	/* Send the data to the AMVP server. */
	ret2 = acvp_net_op(module_ctx, url, &versiondata, &response,
			   acvp_http_post_multi);

	ret = acvp_request_error_handler(ret2);
	if (ret)
		goto out;

	CKINT(_amvp_certrequest_status(certreq_ctx, &response,
				       amvp_certrequest_status_show_status));

	/*
	 * Only a successful upload will allow us to store the digest of the
	 * SP template.
	 */
	if (!state->sp_template_hash) {
		state->sp_template_hash = calloc(1, AMVP_SP_HASH_SIZE);
		CKNULL(state->sp_template_hash, -ENOMEM);
	}
	memcpy(state->sp_template_hash, hash, sizeof(hash));

out:
	amvp_write_status(module_ctx);

	if (filedata.buf && filedata.buf != MAP_FAILED)
		munmap(filedata.buf, (size_t)statbuf.st_size);
	if (fd >= 0)
		close(fd);
	acvp_free_buf(&response);
	return ret;
}

static int amvp_sp_handle_response(const struct acvp_vsid_ctx *certreq_ctx,
				   const struct acvp_buf *response)
{
	int ret;

	CKINT(_amvp_certrequest_status(certreq_ctx, response,
				       amvp_certrequest_status_show_status));

out:
	return ret;
}

static int amvp_sp_add_one(const struct acvp_testid_ctx *module_ctx,
			   uint32_t chapter, struct json_object *src,
			   struct json_object *dst, bool *sp_part_added)
{
	struct amvp_state *state = module_ctx->amvp_state;
	struct json_object_iter sp_data;
	int ret = 0;

	CKNULL(dst, -EINVAL);
	/* Allow empty definitions */
	if (!src)
		return 0;

	if (state) {
		HASH_CTX_ON_STACK(ctx);
		uint8_t hash[AMVP_SP_HASH_SIZE];
		const char *json_request;

		json_request = json_object_to_json_string_ext(
			src,
			JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
		CKNULL_LOG(json_request, -ENOMEM,
			   "JSON object conversion into string failed\n");

		sha256->init(ctx);
		sha256->update(ctx, (const uint8_t *)json_request,
			       strlen(json_request));
		sha256->final(ctx, hash);

		if (state->sp_chapter_hash[chapter]) {
			if (!memcmp(state->sp_chapter_hash[chapter], hash,
				    sizeof(hash))) {
				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "Skipping chapter %u that was already received by the server\n",
				       chapter);
				return 0;
			}
		} else {
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "SP chapter %u that was not yet received by the server\n",
			       chapter);
			state->sp_chapter_hash[chapter] =
				calloc(1, AMVP_SP_HASH_SIZE);
			CKNULL(state->sp_chapter_hash[chapter], -ENOMEM);
		}

		memcpy(state->sp_chapter_hash[chapter], hash, sizeof(hash));
	}

	*sp_part_added = true;

	json_object_object_foreachC(src, sp_data) {
		CKINT(json_object_object_add(dst, sp_data.key, sp_data.val));
		json_object_get(sp_data.val);
	}

out:
	return ret;
}

/*
 * POST /amv/v1/certRequests/<id>/securityPolicy
 */
static int amvp_sp_send_content(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct definition *def = module_ctx->def;
	const struct amvp_def *amvp = def->amvp;
	struct amvp_state *state = module_ctx->amvp_state;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_EXT_BUFFER_INIT(request);
	ACVP_BUFFER_INIT(response);
	struct json_object *sp_head, *sp_data;
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;
	bool sp_part_added = false;

	if (state->sp_state >= AMVP_REQUEST_STATE_PENDING_GENERATION) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Server claims to have received all SP data, but sending potentially updated SP data nonetheless.\n");
	}

	sp_head = json_object_new_object();
	CKNULL(sp_head, ENOMEM);
	CKINT(acvp_req_add_version(sp_head));

	sp_data = json_object_new_object();
	CKNULL(sp_data, ENOMEM);
	CKINT(json_object_object_add(sp_head, "securityPolicy", sp_data));

	CKINT(json_object_object_add(sp_data, "schemaVersion",
				     json_object_new_string("2.8.4")));

	CKINT(amvp_sp_add_one(module_ctx, 0, amvp->sp_general, sp_data,
			      &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 1, amvp->sp_crypt_mod_spec,
			      sp_data, &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 2, amvp->sp_crypt_mod_interfaces,
			      sp_data, &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 3, amvp->sp_roles_services,
			      sp_data, &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 4, amvp->sp_sw_fw_sec, sp_data,
			      &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 5, amvp->sp_oe, sp_data,
			      &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 6, amvp->sp_phys_sec, sp_data,
			      &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 7, amvp->sp_non_invasive_sec,
			      sp_data, &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 8, amvp->sp_ssp_mgmt, sp_data,
			      &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 9, amvp->sp_self_tests, sp_data,
			      &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 10, amvp->sp_lifecycle, sp_data,
			      &sp_part_added));
	CKINT(amvp_sp_add_one(module_ctx, 11,
			      amvp->sp_mitigation_other_attacks, sp_data,
			      &sp_part_added));

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_SECURITY_POLICY));

	if (!sp_part_added) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "All existing SP parts have already been submitted, refraining from submitting again\n");
		/* Now let us stop processing as SP has been uploaded */
		goto out;
	}

	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				sp_head,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		sp_head,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	request.buf = (uint8_t *)json_request;
	request.len = (uint32_t)strlen(json_request);

	ret2 = acvp_net_op(module_ctx, url, &request, &response,
			   acvp_http_post);
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_request_error_handler(ret2));

	logger_status(LOGGER_C_ANY,
		      "Available SP data uploaded to NIST server\n");

	CKINT(amvp_sp_handle_response(certreq_ctx, &response));

out:
	if (ret) {
		/*
		 * Delete all sections that were allegedly submitted in case of
		 * an error.
		 */
		unsigned int i;

		for (i = 0; i < AMVP_SP_LAST_CHAPTER; i++) {
			free(state->sp_chapter_hash[i]);
			state->sp_chapter_hash[i] = NULL;
		}
	}

	amvp_write_status(module_ctx);
	ACVP_JSON_PUT_NULL(sp_head);
	acvp_free_buf(&response);
	return ret;
}

int amvp_sp_upload_evidence(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct amvp_state *state = module_ctx->amvp_state;
	int ret;

	CKINT_LOG(amvp_sp_send_content(certreq_ctx),
		  "SP content submission failed\n");

	/*
	 * Waiting for the server to have the submission processed
	 */
	while (state->sp_state ==
	       AMVP_REQUEST_STATE_PENDING_PROCESSING_SUBMISSION) {
		logger_status(LOGGER_C_ANY,
			      "Waiting for the AMVP server to have SP content processed\n");\
		CKINT(sleep_interruptible(3, &acvp_op_interrupted));

		/* Get the submission status of the SP */
		CKINT(amvp_certrequest_status(
			certreq_ctx, amvp_certrequest_status_show_none));
	}

	CKINT_LOG(amvp_sp_send_template(certreq_ctx),
		  "SP template submission failed\n");

out:
	return ret;
}

int amvp_sp_gen_pdf(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct amvp_state *state = module_ctx->amvp_state;
	int ret;

	CKINT(amvp_sp_upload_evidence(certreq_ctx));

	/*
	 * Waiting for the server to have the submission processed
	 */
	while (state->sp_state < AMVP_REQUEST_STATE_PENDING_GENERATION) {
		logger_status(LOGGER_C_ANY,
			      "Waiting for the AMVP server to have SP template processed\n");\
		CKINT(sleep_interruptible(3, &acvp_op_interrupted));

		/* Get the submission status of the SP */
		CKINT(amvp_certrequest_status(
			certreq_ctx, amvp_certrequest_status_show_none));
	}

	CKINT(amvp_sp_get_pdf(certreq_ctx));

out:
	return ret;
}
