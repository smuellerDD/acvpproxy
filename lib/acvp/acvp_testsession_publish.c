/* ACVP proxy protocol handler for publishing test results
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

#include <string.h>

#include "acvpproxy.h"
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"
#include "threading_support.h"

/* GET /testSessions/<testSessionId> */
int acvp_get_testid_metadata(const struct acvp_testid_ctx *testid_ctx,
			     struct acvp_buf *response_buf)
{
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_testid_url(testid_ctx, url, sizeof(url), false));

	ret2 = acvp_process_retry_testid(testid_ctx, response_buf, url);

	if (!response_buf->buf || !response_buf->len) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "ACVP server did not provide meta data for testSession ID %u\n",
		       testid_ctx->testid);
		ret = -EINVAL;
		goto out;
	}

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response: %s\n", response_buf->buf);

	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

out:
	return ret;
}

static int acvp_publish_write_id(const struct acvp_testid_ctx *testid_ctx,
				 const uint32_t validation_id, bool write_zero)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_BUFFER_INIT(tmp);
	int ret;
	char msgid[12];

	if (!write_zero && !validation_id)
		return 0;

	if (req_details->dump_register)
		return 0;

	snprintf(msgid, sizeof(msgid), "%u", validation_id);
	tmp.buf = (uint8_t *)msgid;
	tmp.len = (uint32_t)strlen(msgid);
	CKINT(ds->acvp_datastore_write_testid(
		testid_ctx, datastore->testsession_certificate_id, true, &tmp));

out:
	return ret;
}

/* GET /validations/<certificateId> */
static int acvp_get_certificate_info(const struct acvp_testid_ctx *testid_ctx,
				     const uint32_t certificate_id)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_BUFFER_INIT(response);
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	if (req_details->dump_register)
		return 0;

	if (!certificate_id)
		return -EINVAL;

	CKINT(acvp_create_url(NIST_VAL_OP_VALIDATIONS, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u", certificate_id));
	CKINT(acvp_net_op(testid_ctx, url, NULL, &response, acvp_http_get));
	CKINT(acvp_store_file(testid_ctx, &response, 1,
			      datastore->testsession_certificate_info));

	logger_status(LOGGER_C_ANY, "Certificate details obtained\n");
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Certificate details:\n%s\n",
	       response.buf);

out:
	acvp_free_buf(&response);
	return ret;
}

/* PUT /testSessions/<testSessionId> */
static int acvp_publish_request(const struct acvp_testid_ctx *testid_ctx,
				struct json_object *publish)
{
	uint32_t certificate_id = 0;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_testid_url(testid_ctx, url, sizeof(url), false));

	ret = acvp_meta_register(testid_ctx, publish, url, sizeof(url),
				 &certificate_id, acvp_http_put);

	/*
	 * We always try to write the ID. If the ID is 0, acvp_publish_write_id
	 * will not write it. In case of success (valid ID returned) or -EAGAIN
	 * (a request ID is returned), the ID is written to disk.
	 */
	ret |= acvp_publish_write_id(testid_ctx, certificate_id, false);

	if (ret)
		goto out;

	CKINT(acvp_get_certificate_info(testid_ctx, certificate_id));

out:
	return ret;
}

static int acvp_publish_ready(const struct acvp_testid_ctx *testid_ctx)
{
	struct json_object *req = NULL, *entry = NULL;
	ACVP_BUFFER_INIT(response);
	int ret;
	bool val;

	CKINT(acvp_get_testid_metadata(testid_ctx, &response));

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(&response, &req, &entry));

	/* Check that all test vectors passed */
	CKINT(json_get_bool(entry, "passed", &val));
	if (!val) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP server reports that not all vectors for testID %u passed - rejecting to publish\n",
		       testid_ctx->testid);
		ret = -EBADMSG;
		goto out;
	}

	/* Check that vector is publishable */
	CKINT(json_get_bool(entry, "publishable", &val));
	if (!val) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP server reports that testID %u is not publishable - rejecting to publish\n",
		       testid_ctx->testid);
		ret = -EBADMSG;
		goto out;
	}

out:
	ACVP_JSON_PUT_NULL(req);
	acvp_free_buf(&response);
	return ret;
}

static int acvp_publish_prereqs(const struct acvp_testid_ctx *testid_ctx,
				struct json_object *pub)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_test_deps *deps = testid_ctx->deps;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct definition *def = testid_ctx->def;
	struct json_object *prereq, *entry = NULL;
	unsigned int i;
	int ret = 0;

	if (ctx_opts->no_publish_prereqs)
		return 0;

	prereq = json_object_new_array();
	CKNULL(prereq, -ENOMEM);
	for (i = 0; i < def->num_algos; i++) {
		const struct def_algo *def_algo = def->algos + i;

		entry = json_object_new_object();
		CKNULL(entry, -ENOMEM);

		switch (def_algo->type) {
		case DEF_ALG_TYPE_SYM:
			CKINT(acvp_req_set_prereq_sym(&def_algo->algo.sym, deps,
						      entry, true));
			break;
		case DEF_ALG_TYPE_SHA:
			/* no prereq */
			break;
		case DEF_ALG_TYPE_SHAKE:
			/* no prereq */
			break;
		case DEF_ALG_TYPE_HMAC:
			CKINT(acvp_req_set_prereq_hmac(&def_algo->algo.hmac,
						       deps, entry, true));
			break;
		case DEF_ALG_TYPE_CMAC:
			CKINT(acvp_req_set_prereq_cmac(&def_algo->algo.cmac,
						       deps, entry, true));
			break;
		case DEF_ALG_TYPE_DRBG:
			CKINT(acvp_req_set_prereq_drbg(&def_algo->algo.drbg,
						       deps, entry, true));
			break;
		case DEF_ALG_TYPE_RSA:
			CKINT(acvp_req_set_prereq_rsa(&def_algo->algo.rsa, deps,
						      entry, true));
			break;
		case DEF_ALG_TYPE_ECDSA:
			CKINT(acvp_req_set_prereq_ecdsa(&def_algo->algo.ecdsa,
							deps, entry, true));
			break;
		case DEF_ALG_TYPE_EDDSA:
			CKINT(acvp_req_set_prereq_eddsa(&def_algo->algo.eddsa,
							deps, entry, true));
			break;
		case DEF_ALG_TYPE_DSA:
			CKINT(acvp_req_set_prereq_dsa(&def_algo->algo.dsa, deps,
						      entry, true));
			break;
		case DEF_ALG_TYPE_KAS_ECC:
			CKINT(acvp_req_set_prereq_kas_ecc(
				&def_algo->algo.kas_ecc, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KAS_FFC:
			CKINT(acvp_req_set_prereq_kas_ffc(
				&def_algo->algo.kas_ffc, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_SSH:
			CKINT(acvp_req_set_prereq_kdf_ssh(
				&def_algo->algo.kdf_ssh, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_IKEV1:
			CKINT(acvp_req_set_prereq_kdf_ikev1(
				&def_algo->algo.kdf_ikev1, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_IKEV2:
			CKINT(acvp_req_set_prereq_kdf_ikev2(
				&def_algo->algo.kdf_ikev2, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_TLS:
			CKINT(acvp_req_set_prereq_kdf_tls(
				&def_algo->algo.kdf_tls, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_TLS12:
			CKINT(acvp_req_set_prereq_kdf_tls12(
				&def_algo->algo.kdf_tls, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_TLS13:
			CKINT(acvp_req_set_prereq_kdf_tls13(
				&def_algo->algo.kdf_tls13, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_108:
			CKINT(acvp_req_set_prereq_kdf_108(
				&def_algo->algo.kdf_108, deps, entry, true));
			break;
		case DEF_ALG_TYPE_PBKDF:
			CKINT(acvp_req_set_prereq_pbkdf(&def_algo->algo.pbkdf,
							deps, entry, true));
			break;
		case DEF_ALG_TYPE_KAS_FFC_R3:
			CKINT(acvp_req_set_prereq_kas_ffc_r3(
				&def_algo->algo.kas_ffc_r3, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KAS_ECC_R3:
			CKINT(acvp_req_set_prereq_kas_ecc_r3(
				&def_algo->algo.kas_ecc_r3, deps, entry, true));
			break;
		case DEF_ALG_TYPE_SAFEPRIMES:
			CKINT(acvp_req_set_prereq_safeprimes(
				&def_algo->algo.safeprimes, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KAS_IFC:
			CKINT(acvp_req_set_prereq_kas_ifc(
				&def_algo->algo.kas_ifc, deps, entry, true));
			break;
		case DEF_ALG_TYPE_HKDF:
			CKINT(acvp_req_set_prereq_hkdf(&def_algo->algo.hkdf,
						       deps, entry, true));
			break;
		case DEF_ALG_TYPE_COND_COMP:
			CKINT(acvp_req_set_prereq_cond_comp(
				&def_algo->algo.cond_comp, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_ONESTEP:
			CKINT(acvp_req_set_prereq_kdf_onestep(
				&def_algo->algo.kdf_onestep, deps, entry,
				true));
			break;
		case DEF_ALG_TYPE_KDF_TWOSTEP:
			CKINT(acvp_req_set_prereq_kdf_twostep(
				&def_algo->algo.kdf_twostep, deps, entry,
				true));
			break;
		case DEF_ALG_TYPE_KDF_TPM:
			CKINT(acvp_req_set_prereq_kdf_tpm(
				&def_algo->algo.kdf_tpm, deps, entry, true));
			break;
		case DEF_ALG_TYPE_ANSI_X963:
			CKINT(acvp_req_set_prereq_ansi_x963(
				&def_algo->algo.ansi_x963, deps, entry, true));
			break;
		case DEF_ALG_TYPE_KDF_SRTP:
			CKINT(acvp_req_set_prereq_kdf_srtp(
				&def_algo->algo.kdf_srtp, deps, entry, true));
			break;
		case DEF_ALG_TYPE_XOF:
			/* no prereq */
			break;
		case DEF_ALG_TYPE_ANSI_X942:
			CKINT(acvp_req_set_prereq_ansi_x942(
				&def_algo->algo.ansi_x942, deps, entry, true));
			break;
		case DEF_ALG_TYPE_LMS:
			CKINT(acvp_req_set_prereq_lms(
				&def_algo->algo.lms, deps, entry, true));
			break;

		default:
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Unknown algorithm definition type\n");
			ret = -EINVAL;
			goto out;
			break;
		}

		if (json_object_object_length(entry) > 0) {
			CKINT(json_object_array_add(prereq, entry));
			entry = NULL;
		} else {
			ACVP_JSON_PUT_NULL(entry);
		}
	}

	if (json_object_array_length(prereq) > 0) {
		CKINT(json_object_object_add(pub, "algorithmPrerequisites",
					     prereq));
		logger(LOGGER_DEBUG, LOGGER_C_ANY, "New prerequisites array\n");
	} else {
		ACVP_JSON_PUT_NULL(prereq);
	}

out:
	ACVP_JSON_PUT_NULL(entry);
	return ret;
}

static int acvp_publish_build(const struct acvp_testid_ctx *testid_ctx,
			      struct json_object **json_publish)
{
	const struct definition *def = testid_ctx->def;
	const struct def_info *def_info = def->info;
	const struct def_oe *def_oe = def->oe;
	struct json_object *pub = NULL;
	int ret = -EINVAL;
	char url[ACVP_NET_URL_MAXLEN];

	if (!def_info->acvp_module_id) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No module or OE ID for test ID %u (%s) found\n",
		       testid_ctx->testid, def_info->module_name);
		return -EINVAL;
	}

	/*
	 * {
	 *	"moduleUrl": "/acvp/v1/modules/20",
	 *	"oeUrl": "/acvp/v1/oes/60",
	 *	"algorithmPrerequisites": [{
	 *		"algorithm": "AES-GCM",
	 *		"prerequisites": [
	 *			{
	 *				"algorithm": "AES",
	 *				"validationId": "123456"
	 *			},
	 *			{
	 *				"algorithm": "DRBG",
	 *				"validationId": "123456"
	 *			}
	 *		]
	 *	}],
	 *	"signature": {
	 *		"algorithm": "SHA256RSA",
	 *		"certificate": "{base64encodedcertificate}",
	 *		"digitalSignature": "{base64encodedsignature}"
	 *	}
	 * }
	 */

	/*
	 * The prerequisites are optional if they are always included into
	 * the original requests. This is the case with our ACVP Proxy.
	 * Thus, we do not add those.
	 */

	/* Build the JSON object to be submitted */
	pub = json_object_new_object();
	CKNULL(pub, -ENOMEM);

	CKINT(acvp_create_urlpath(NIST_VAL_OP_MODULE, url, sizeof(url)));
	CKINT(acvp_extend_string(url, sizeof(url), "/%u",
				 def_info->acvp_module_id));
	CKINT(json_object_object_add(pub, "moduleUrl",
				     json_object_new_string(url)));

	if (def_oe->acvp_oe_id) {
		CKINT(acvp_create_urlpath(NIST_VAL_OP_OE, url, sizeof(url)));
		CKINT(acvp_extend_string(url, sizeof(url), "/%u",
					 def_oe->acvp_oe_id));
		CKINT(json_object_object_add(pub, "oeUrl",
					     json_object_new_string(url)));
	}

	//TODO: reenable once issue 749 is fixed
	if (0)
		CKINT(acvp_publish_prereqs(testid_ctx, pub));

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, pub, "Vendor JSON object");

	*json_publish = pub;

	return 0;

out:
	ACVP_JSON_PUT_NULL(pub);
	return ret;
}

static void acvp_test_del_deps(struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_test_deps *deps;

	if (!testid_ctx || !testid_ctx->deps)
		return;

	deps = testid_ctx->deps;

	while (deps) {
		struct acvp_test_deps *tmp = deps->next;

		ACVP_PTR_FREE_NULL(deps->dep_cert);
		ACVP_PTR_FREE_NULL(deps);

		/*
		 * deps->dep_cipher is freed by the deallocation of the
		 * definition.
		 */

		deps = tmp;
	}
}

/*
 * The concept of configured dependencies is as follows:
 * During start time, the user configuration is parsed into the linked list
 * of definition->deps. This list only contains the dependencies between
 * module definitions. At this point the dependency list is applied
 * by assigning certificate IDs to each dependency. This is achieved by
 * iterating through definition->deps and using each dependency in a new
 * search query to find all test session IDs that are covered by the definition.
 * The first test session in that list is identified to have a certificate ID
 * the certificate ID for this dependency is stored in testid_ctx->deps.
 *
 * testid_ctx->deps is finally applied when the prerequisite JSON structure
 * is created.
 */
static int acvp_test_add_deps(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx;
	const struct definition *def;
	const struct def_info *info;
	const struct def_deps *def_deps;
	struct acvp_test_deps *test_deps;
	struct acvp_testid_ctx tmp_testid_ctx;
	uint32_t testids[ACVP_REQ_MAX_FAILED_TESTID];
	unsigned int i, testid_count = ACVP_REQ_MAX_FAILED_TESTID;
	int ret = 0;

	if (!testid_ctx)
		return 0;

	memset(&tmp_testid_ctx, 0, sizeof(tmp_testid_ctx));

	def = testid_ctx->def;
	CKNULL_LOG(def, -EINVAL, "Definition structure is NULL\n");

	if (!def->deps)
		return 0;

	ctx = testid_ctx->ctx;
	test_deps = testid_ctx->deps;
	info = def->info;

	/* Iterate through the configured dependencies */
	for (def_deps = def->deps; def_deps != NULL;
	     def_deps = def_deps->next) {
		/*
		 * As we found a new dependency, prepare a new entry in the
		 * testid_ctx linked list to hold the dependency with a
		 * certificate.
		 */
		if (test_deps) {
			/* fast-forward to the end */
			while (test_deps->next)
				test_deps = test_deps->next;

			test_deps->next = calloc(1, sizeof(*test_deps));
			CKNULL(test_deps->next, -ENOMEM);
			test_deps = test_deps->next;
		} else {
			/* First entry */
			test_deps = calloc(1, sizeof(*test_deps));
			CKNULL(test_deps, -ENOMEM);
			testid_ctx->deps = test_deps;
		}

		/* Store the cipher name of the dependency */
		test_deps->dep_cipher = def_deps->dep_cipher;

		/*
		 * Manual dependency handling
		 */
		if (def_deps->deps_type == acvp_deps_manual_resolution) {
			CKNULL_LOG(def_deps->dep_name, -EINVAL,
				   "Certificate reference missing");
			CKINT(acvp_duplicate(&test_deps->dep_cert,
					     def_deps->dep_name));

			continue;
		}

		/* Automated dependency handling */

		/*
		 * Search for all testids for the given dependency
		 *
		 * Note, this search operation is limited by the search
		 * testid and vsid search criteria, i.e. when the user only
		 * requests the processing of a given set of test sessions or
		 * vector set IDs.
		 */
		CKINT(ds->acvp_datastore_find_testsession(
			def_deps->dependency, ctx, testids, &testid_count));

		/*
		 * Iterate through all testids returned by the search and
		 * find one with a cert.
		 */
		for (i = 0; i < testid_count; i++) {
			struct acvp_auth_ctx *auth;

			tmp_testid_ctx.def = def_deps->dependency;
			tmp_testid_ctx.ctx = ctx;
			tmp_testid_ctx.testid = testids[i];

			CKINT(acvp_init_auth(&tmp_testid_ctx));
			/* Get authtoken and cert ID if available */
			CKINT(ds->acvp_datastore_read_authtoken(
				&tmp_testid_ctx));
			auth = tmp_testid_ctx.server_auth;

			if (auth->testsession_certificate_number) {
				/* We found a certificate, store it */
				CKINT(acvp_duplicate(
					&test_deps->dep_cert,
					auth->testsession_certificate_number));

				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "Dependency  certificate for cipher type %s found: %s\n",
				       test_deps->dep_cipher,
				       test_deps->dep_cert);

				acvp_release_auth(&tmp_testid_ctx);

				/* once we found one entry, we stop */
				break;
			}
			acvp_release_auth(&tmp_testid_ctx);
		}

		if (!test_deps->dep_cert) {
			logger_status(
				LOGGER_C_ANY,
				"No certificate found for dependency cipher %s for module %s - skipping module implementation (invoke operation again once the certificate is obtained)\n",
				test_deps->dep_cipher, info->module_name);
			ret = -EAGAIN;
			goto out;
		}
	}

out:
	acvp_release_auth(&tmp_testid_ctx);
	return ret;
}

static int acvp_publish_testid(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *ctx_opts = &ctx->options;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct acvp_auth_ctx *auth;
	struct json_object *json_publish = NULL;
	int ret, ret2;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP volatile request context missing\n");

	logger_status(LOGGER_C_ANY, "Publishing testID %u\n",
		      testid_ctx->testid);

	CKINT(acvp_init_auth(testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/* Check if we have an outstanding test session cert ID requests */
	auth = testid_ctx->server_auth;
	ret2 = acvp_meta_obtain_request_result(
		testid_ctx, &auth->testsession_certificate_id);
	CKINT(acvp_publish_write_id(testid_ctx,
				    auth->testsession_certificate_id, true));
	if (ret2 < 0) {
		ret = ret2;
		goto out;
	}

	CKINT(acvp_handle_open_requests(testid_ctx));

	/*
	 * If we have an ID and reach here, it is a valid test session
	 * certificate ID and we stop processing.
	 */
	if (!req_details->dump_register && !ctx_opts->delete_db_entry &&
	    !ctx_opts->update_db_entry && auth->testsession_certificate_id) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Test session certificate ID %u %s obtained\n",
		       auth->testsession_certificate_id,
		       acvp_valid_id(auth->testsession_certificate_id) ?
				     "successfully" :
				     "not yet");
		logger_status(LOGGER_C_ANY,
			      "Test session certificate ID %u %s obtained\n",
			      auth->testsession_certificate_id,
			      acvp_valid_id(auth->testsession_certificate_id) ?
					    "successfully" :
					    "not yet");

		if (acvp_valid_id(auth->testsession_certificate_id))
			CKINT(acvp_get_certificate_info(
				testid_ctx, auth->testsession_certificate_id));

		ret = 0;
		goto out;
	}

	/* Will the ACVP server accept our publication request? */
	if (!req_details->dump_register) {
		if (acvp_publish_ready(testid_ctx)) {
			ret = 0;
			goto out;
		}
	}

	CKINT(acvp_sync_metadata(testid_ctx));

	/*
	 * Resolve dependencies if configured. If we are at this point,
	 * we are going to request a certificate and are about to publish
	 * dependencies. If dependencies are configured, we require that
	 * we have a certificate from the depending test sessions at this
	 * point. If not, we stop here to let the other certificate requests
	 * to pass hoping that when they receive a certificate, we can
	 * progress during the next round.
	 */
	CKINT(acvp_test_add_deps(testid_ctx));

	/* Create publication JSON data */
	CKINT(acvp_publish_build(testid_ctx, &json_publish));

	/* Do it: send the publication request to the ACVP server */
	CKINT(acvp_publish_request(testid_ctx, json_publish));

out:
	acvp_release_auth(testid_ctx);
	ACVP_JSON_PUT_NULL(json_publish);
	/* -EAGAIN is no error code */
	if (ret == -EAGAIN)
		ret = 0;
	return ret;
}

static int _acvp_publish(const struct acvp_ctx *ctx,
			 const struct definition *def, const uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;
	testid_ctx->testid = testid;

	if (clock_gettime(CLOCK_REALTIME, &testid_ctx->start)) {
		ret = -errno;
		goto out;
	}

	CKINT(acvp_publish_testid(testid_ctx));

out:
	acvp_test_del_deps(testid_ctx);
	acvp_release_testid(testid_ctx);

	return ret;
}

DSO_PUBLIC
int acvp_publish(struct acvp_ctx *ctx)
{
	struct acvp_opts_ctx *ctx_opts = &ctx->options;
	int ret;

	CKINT(acvp_testids_refresh(ctx, acvp_init_testid_ctx, NULL, NULL));

	/*
	 * Force disabling of threading - the ACVP server performs
	 * synchronous operations during publish, so we do not need to
	 * enable threading.
	 *
	 * Also, threading is a problem because, if, say, we have one
	 * module "abc" with two OEs and both module instances are registered
	 * with one acvp_publish invocation, only one register operation
	 * of the module should take place. With threading enabled there
	 * will be two operations though, because the checking whether
	 * a request is already pending will be done before hitting the server.
	 * This implies that the proxy assumes there is no pending registration
	 * at the moment. Once the first registration succeeds, the 2nd
	 * pending request in the separate thread is not updated any more.
	 *
	 * Thus, all requests should be done serially.
	 */
	ctx_opts->threading_disabled = true;
	CKINT(acvp_process_testids(ctx, &_acvp_publish));

out:
	return ret;
}

DSO_PUBLIC
int acvp_synchronize_metadata(const struct acvp_ctx *ctx)
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	const struct definition *def;
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	datastore = &ctx->datastore;
	search = &datastore->search;

	/* Find a module definition */
	def = acvp_find_def(search, NULL);
	if (!def) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No cipher implementation found for search criteria\n");
		return -EINVAL;
	}

	/*
	 * Use thread group 0 for the register of cipher definitions and
	 * thread group 1 for the vsID downloads.
	 *
	 * We have threads to register one cipher definition. While the thread
	 * for registering one cipher definition is still running, threads are
	 * spawned to download the vsIDs.
	 *
	 * The threads for registering cipher definitions are spawned all at
	 * the beginning (to the extent possible). Thus, if we have more cipher
	 * definitions to be registered at the same time as threads, we will
	 * not be able to spawn any thread for downloading a vsID which will
	 * cause a deadlock. Thus, we use different thread groups for
	 * these interdependent threads to prevent that there can be a deadlock.
	 */
	while (def) {
		testid_ctx = calloc(1, sizeof(struct acvp_testid_ctx));
		CKNULL(testid_ctx, -ENOMEM);

		testid_ctx->ctx = ctx;
		testid_ctx->def = def;

		CKINT(acvp_init_auth(testid_ctx));

		/*
		 * No threading as this is a synchronous request -
		 * see comment in acvp_publish.
		 */
		ret = acvp_sync_metadata(testid_ctx);
		/*
		 * -EAGAIN means that something was registered - this is an
		 * expected return code and does not indicate an error here.
		 */
		if (ret == -EAGAIN)
			ret = 0;
		else if (ret < 0)
			goto out;

		acvp_release_auth(testid_ctx);
		ACVP_PTR_FREE_NULL(testid_ctx);

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

out:
	acvp_release_auth(testid_ctx);
	ACVP_PTR_FREE_NULL(testid_ctx);
	return ret;
}
