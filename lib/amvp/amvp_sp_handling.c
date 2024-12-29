/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "amvp_internal.h"
#include "base64.h"
#include "internal.h"
#include "request_helper.h"

static int amvp_sp_handle_get_pdf_response(
	const struct acvp_vsid_ctx *certreq_ctx, struct acvp_buf *response)
{
	uint8_t *pdf = NULL, *digest = NULL;
	size_t pdflen, digestlen;
	const char *str;
	struct json_object *resp = NULL, *data = NULL;
	int ret;

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));
	CKINT(json_get_string(data, "status", &str));

	if (!strncasecmp(str, "success", 7)) {
		HASH_CTX_ON_STACK(ctx);
		ACVP_BUFFER_INIT(pdfbuf);
		char spfile[100];
		uint8_t digest_compare[AMVP_SP_HASH_SIZE];

		logger_status(LOGGER_C_ANY, "Security Policy downloaded\n");

		/* Get the PDF which is base64 encoded and decode it */
		CKINT(json_get_string(data, "content", &str));
		CKINT(base64_decode(str, strlen(str), &pdf, &pdflen));
		if (pdflen > UINT32_MAX) {
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
		sha256->update(ctx, pdf, pdflen);
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
		pdfbuf.buf = pdf;
		pdfbuf.len = (uint32_t)pdflen;

		/* Generate file name of Security Policy */
		snprintf(spfile, sizeof(spfile), "%u%s", certreq_ctx->vsid,
			 AMVP_DS_SP_FILENAME);

		CKINT(ds->acvp_datastore_write_vsid(certreq_ctx, spfile,
						    false, &pdfbuf));
		logger_status(LOGGER_C_ANY,
			      "Security Policy PDF file stored in certificate request %u database directory\n",
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
	if (pdf)
		free(pdf);
	if (digest)
		free(digest);
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

/*
 * GET /amv/v1/certRequests/<id>/securityPolicy
 */
int amvp_sp_get_pdf(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_SECURITY_POLICY));

	ret2 = acvp_net_op(module_ctx, url, NULL, &response, acvp_http_get);
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_sp_handle_get_pdf_response(certreq_ctx, &response));

out:
	acvp_free_buf(&response);
	return ret;
}

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
	CKINT(json_find_key(data, "missingSecurityPolicySection", &sp,
			    json_type_array));
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
	}

	str = json_object_to_json_string_ext(
		sp, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(str, -ENOMEM,
		   "JSON object conversion into string failed\n");

	stat.buf = (uint8_t *)str;
	stat.len = (uint32_t)strlen(str);

	CKINT(acvp_store_file(module_ctx, &stat, 1, "sp_status.json"));

	CKINT(amvp_write_status(module_ctx));

out:
	return ret;
}

static int amvp_sp_handle_response(const struct acvp_vsid_ctx *certreq_ctx,
				   const struct acvp_buf *response)
{
	struct json_object *resp = NULL, *data = NULL;
	int ret;

	/* Strip the version array entry and get the oe URI data. */
	CKINT(acvp_req_strip_version(response, &resp, &data));

	CKINT(amvp_sp_status(certreq_ctx, data));

out:
	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

static int amvp_sp_add_one(const struct acvp_vsid_ctx *certreq_ctx,
			   uint32_t chapter, struct json_object *src,
			   struct json_object *dst)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	struct amvp_state *state = module_ctx->amvp_state;
	struct json_object_iter sp_data;
	int ret;

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
				    AMVP_SP_HASH_SIZE)) {
				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "Skipping chapter %u that was already received by the server\n",
				       chapter);
				return 0;
			}
		} else {
			state->sp_chapter_hash[chapter] =
				calloc(1, AMVP_SP_HASH_SIZE);
			CKNULL(state->sp_chapter_hash[chapter], -ENOMEM);
		}

		memcpy(state->sp_chapter_hash[chapter], hash,
		       AMVP_SP_HASH_SIZE);
	}

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
int amvp_sp_upload_evidence(const struct acvp_vsid_ctx *certreq_ctx)
{
	const struct acvp_testid_ctx *module_ctx = certreq_ctx->testid_ctx;
	const struct definition *def = module_ctx->def;
	const struct amvp_def *amvp = def->amvp;
	const struct acvp_ctx *ctx = module_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_EXT_BUFFER_INIT(request);
	ACVP_BUFFER_INIT(response);
	struct json_object *sp, *sp_head, *sp_data;
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;

struct json_object *mockup;

	sp = json_object_new_array();
	CKNULL(sp, -ENOMEM);
	CKINT(acvp_req_add_version(sp));

	sp_head = json_object_new_object();
	CKNULL(sp_head, ENOMEM);
	CKINT(json_object_array_add(sp, sp_head));

	sp_data = json_object_new_object();
	CKNULL(sp_data, ENOMEM);
	CKINT(json_object_object_add(sp_head, "securityPolicy", sp_data));

	/* The general section must be present */
	CKNULL(amvp->sp_general, -EINVAL);
	CKINT(amvp_sp_add_one(certreq_ctx, 0, amvp->sp_general, sp_data));

mockup = json_object_new_object();
CKNULL(mockup, ENOMEM);
CKINT(json_object_object_add(mockup, "cryptographicModuleSpecification", json_object_new_object()));
CKINT(amvp_sp_add_one(certreq_ctx, 1, mockup, sp_data));
ACVP_JSON_PUT_NULL(mockup);
//	CKINT(amvp_sp_add_one(certreq_ctx, 1, amvp->sp_crypt_mod_spec,
//			      sp_data));
	CKINT(amvp_sp_add_one(certreq_ctx, 2, amvp->sp_crypt_mod_interfaces,
			      sp_data));
	CKINT(amvp_sp_add_one(certreq_ctx, 3, amvp->sp_roles_services,
			      sp_data));
	CKINT(amvp_sp_add_one(certreq_ctx, 4, amvp->sp_sw_fw_sec, sp_data));

mockup = json_object_new_object();
CKNULL(mockup, ENOMEM);
CKINT(json_object_object_add(mockup, "operationalEnvironment", json_object_new_object()));
CKINT(amvp_sp_add_one(certreq_ctx, 5, mockup, sp_data));
ACVP_JSON_PUT_NULL(mockup);
//	CKINT(amvp_sp_add_one(certreq_ctx, 5, amvp->sp_oe, sp_data));

mockup = json_object_new_object();
CKNULL(mockup, ENOMEM);
CKINT(json_object_object_add(mockup, "physicalSecurity", json_object_new_object()));
CKINT(amvp_sp_add_one(certreq_ctx, 6, mockup, sp_data));
ACVP_JSON_PUT_NULL(mockup);
//	CKINT(amvp_sp_add_one(certreq_ctx, 6, amvp->sp_phys_sec, sp_data));

mockup = json_object_new_object();
CKNULL(mockup, ENOMEM);
CKINT(json_object_object_add(mockup, "noninvasiveSecurity", json_object_new_object()));
CKINT(amvp_sp_add_one(certreq_ctx, 7, mockup, sp_data));
ACVP_JSON_PUT_NULL(mockup);
//	CKINT(amvp_sp_add_one(certreq_ctx, 7, amvp->sp_non_invasive_sec,
//			      sp_data));
	CKINT(amvp_sp_add_one(certreq_ctx, 8, amvp->sp_ssp_mgmt, sp_data));


mockup = json_object_new_object();
CKNULL(mockup, ENOMEM);
CKINT(json_object_object_add(mockup, "selfTests", json_object_new_object()));
CKINT(amvp_sp_add_one(certreq_ctx, 9, mockup, sp_data));
ACVP_JSON_PUT_NULL(mockup);
//	CKINT(amvp_sp_add_one(certreq_ctx, 9,
//			      amvp->sp_self_tests, sp_data));
	CKINT(amvp_sp_add_one(certreq_ctx, 10, amvp->sp_lifecycle, sp_data));
	CKINT(amvp_sp_add_one(certreq_ctx, 11,
			      amvp->sp_mitigation_other_attacks, sp_data));

	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				sp,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		sp,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	request.buf = (uint8_t *)json_request;
	request.len = (uint32_t)strlen(json_request);

	CKINT_LOG(acvp_create_url(NIST_VAL_OP_CERTREQUESTS, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certreq_ctx->vsid));
	CKINT(acvp_extend_string(url, sizeof(url), "/%s",
				 NIST_VAL_OP_SECURITY_POLICY));

	ret2 = acvp_net_op(module_ctx, url, &request, &response,
			   acvp_http_post);
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_request_error_handler(ret2));

	CKINT(amvp_sp_handle_response(certreq_ctx, &response));

out:
	amvp_write_status(module_ctx);
	ACVP_JSON_PUT_NULL(sp);
	acvp_free_buf(&response);
	return ret;
}
