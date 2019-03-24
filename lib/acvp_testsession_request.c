/* ACVP proxy protocol handler for requesting test vectors
 *
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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
#include <unistd.h>

#include "atomic_bool.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "json_wrapper.h"
#include "request_helper.h"
#include "sleep.h"
#include "threading_support.h"

/*
 * Structure for one thread
 */
struct acvp_thread_ctx {
	struct acvp_vsid_ctx *vsid_ctx;
};

/*
 * Shall the ACVP operation be shut down?
 */
static atomic_bool_t acvp_op_interrupted = ATOMIC_BOOL_INIT(false);

/*****************************************************************************
 * Helper code
 *****************************************************************************/
void acvp_op_interrupt(void)
{
	atomic_bool_set_true(&acvp_op_interrupted);
}

void acvp_op_enable(void)
{
	atomic_bool_set_false(&acvp_op_interrupted);
}

int acvp_testid_url(const struct acvp_testid_ctx *testid_ctx,
		    char *url, uint32_t urllen)
{
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL, "testid_ctx missing\n");
	CKNULL_LOG(url, -EINVAL, "URL buffer missing\n");

	if (!testid_ctx->testid) {
		logger(LOGGER_WARN, LOGGER_C_ANY, "TestID missing\n");
		return -EINVAL;
	}

	CKINT(acvp_create_url(NIST_VAL_OP_REG, url, urllen));
	CKINT(acvp_extend_string(url, urllen, "/%u", testid_ctx->testid));

	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "testID URL: %s\n", url);

out:
	return ret;
}

int acvp_vectorset_url(const struct acvp_testid_ctx *testid_ctx, char *url,
		       uint32_t urllen)
{
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL, "testid_ctx missing\n");
	CKNULL_LOG(url, -EINVAL, "URL buffer missing\n");

	CKINT(acvp_testid_url(testid_ctx, url, urllen));
	CKINT(acvp_extend_string(url, urllen, "/%s", NIST_VAL_OP_VECTORSET));

	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "vectorSet URL: %s\n", url);

out:
	return ret;
}

int acvp_vsid_url(const struct acvp_vsid_ctx *vsid_ctx, char *url,
		  uint32_t urllen)
{
	const struct acvp_testid_ctx *testid_ctx;
	int ret;

	CKNULL_LOG(vsid_ctx, -EINVAL, "vsid_ctx missing\n");
	CKNULL_LOG(url, -EINVAL, "URL buffer missing\n");

	testid_ctx = vsid_ctx->testid_ctx;

	if (!vsid_ctx->vsid) {
		logger(LOGGER_WARN, LOGGER_C_ANY, "vsID missing\n");
		return -EINVAL;
	}

	CKINT(acvp_vectorset_url(testid_ctx, url, urllen));
	CKINT(acvp_extend_string(url, urllen, "/%u", vsid_ctx->vsid));

	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "vsID URL: %s\n", url);

out:
	return ret;
}

void acvp_release_testid(struct acvp_testid_ctx *testid_ctx)
{
	if (!testid_ctx)
		return;

	free(testid_ctx);
}

void acvp_release_vsid_ctx(struct acvp_vsid_ctx *vsid_ctx)
{
	if (!vsid_ctx)
		return;

	free(vsid_ctx);
}

/*****************************************************************************
 * Track testIDs which failed to download completely
 *****************************************************************************/
static uint32_t acvp_req_failed_testid[ACVP_REQ_MAX_FAILED_TESTID];
static atomic_t acvp_req_failed_testid_ptr = ATOMIC_INIT(-1);

static void acvp_record_failed_testid(uint32_t testid)
{
	int idx = atomic_inc(&acvp_req_failed_testid_ptr);

	if (idx < 0 || idx >= ACVP_REQ_MAX_FAILED_TESTID) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Cannot track failed testID %u\n", testid);
		return;
	}

	acvp_req_failed_testid[idx] = testid;
}

DSO_PUBLIC
int acvp_list_failed_testid(int *idx_ptr, uint32_t *testid)
{
	int idx = atomic_read(&acvp_req_failed_testid_ptr);

	if (*idx_ptr > idx)
		return -ENOENT;

	idx = *idx_ptr;

	if (idx < 0 || idx >= ACVP_REQ_MAX_FAILED_TESTID)
		return -ENOENT;

	*testid = acvp_req_failed_testid[idx];
	*idx_ptr = *idx_ptr + 1;

	return 0;
}

/*****************************************************************************
 * Code for registering at the ACVP server and fetching test vectors
 *****************************************************************************/
static int acvp_req_set_algo(struct json_object *algorithms,
			     const struct def_algo *def_algo)
{
	struct json_object *entry = NULL;
	int ret = -EINVAL;

	CKNULL_LOG(algorithms, -EINVAL, "Missing algorithm object\n");

	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);

	switch(def_algo->type) {
	case DEF_ALG_TYPE_SYM:
		CKINT(acvp_req_set_algo_sym(&def_algo->algo.sym, entry));
		break;
	case DEF_ALG_TYPE_SHA:
		CKINT(acvp_req_set_algo_sha(&def_algo->algo.sha, entry));
		break;
	case DEF_ALG_TYPE_SHAKE:
		CKINT(acvp_req_set_algo_shake(&def_algo->algo.shake, entry));
		break;
	case DEF_ALG_TYPE_HMAC:
		CKINT(acvp_req_set_algo_hmac(&def_algo->algo.hmac, entry));
		break;
	case DEF_ALG_TYPE_CMAC:
		CKINT(acvp_req_set_algo_cmac(&def_algo->algo.cmac, entry));
		break;
	case DEF_ALG_TYPE_DRBG:
		CKINT(acvp_req_set_algo_drbg(&def_algo->algo.drbg, entry));
		break;
	case DEF_ALG_TYPE_RSA:
		CKINT(acvp_req_set_algo_rsa(&def_algo->algo.rsa, entry));
		break;
	case DEF_ALG_TYPE_ECDSA:
		CKINT(acvp_req_set_algo_ecdsa(&def_algo->algo.ecdsa, entry));
		break;
	case DEF_ALG_TYPE_EDDSA:
		CKINT(acvp_req_set_algo_eddsa(&def_algo->algo.eddsa, entry));
		break;
	case DEF_ALG_TYPE_DSA:
		CKINT(acvp_req_set_algo_dsa(&def_algo->algo.dsa, entry));
		break;
	case DEF_ALG_TYPE_KAS_ECC:
		CKINT(acvp_req_set_algo_kas_ecc(&def_algo->algo.kas_ecc,
						entry));
		break;
	case DEF_ALG_TYPE_KAS_FFC:
		CKINT(acvp_req_set_algo_kas_ffc(&def_algo->algo.kas_ffc,
						entry));
		break;
	case DEF_ALG_TYPE_KDF_SSH:
		CKINT(acvp_req_set_algo_kdf_ssh(&def_algo->algo.kdf_ssh,
						entry));
		break;
	case DEF_ALG_TYPE_KDF_IKEV1:
		CKINT(acvp_req_set_algo_kdf_ikev1(&def_algo->algo.kdf_ikev1,
						  entry));
		break;
	case DEF_ALG_TYPE_KDF_IKEV2:
		CKINT(acvp_req_set_algo_kdf_ikev2(&def_algo->algo.kdf_ikev2,
						  entry));
		break;
	case DEF_ALG_TYPE_KDF_TLS:
		CKINT(acvp_req_set_algo_kdf_tls(&def_algo->algo.kdf_tls,
						entry));
		break;
	case DEF_ALG_TYPE_KDF_108:
		CKINT(acvp_req_set_algo_kdf_108(&def_algo->algo.kdf_108,
						entry));
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unknown algorithm definition type\n");
		ret = -EINVAL;
		goto out;
		break;
	}

	CKINT(json_object_array_add(algorithms, entry));

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, algorithms,
		    "Algorithms JSON object");

	return 0;

out:
	ACVP_JSON_PUT_NULL(entry);
	return ret;
}

static int acvp_req_build(struct acvp_testid_ctx *testid_ctx,
			  struct json_object *request)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	const struct definition *def = testid_ctx->def;
	struct json_object *entry = NULL, *tmp = NULL, *algorithms = NULL;
	unsigned int i;
	int ret = 0;

	/* Array entry for version */
	CKINT(acvp_req_add_version(request));

	/* Array entry for request */
	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);

	CKINT(json_object_object_add(entry, "isSample",
	       json_object_new_boolean(ctx->req_details.request_sample)));

	CKINT(json_object_object_add(entry, "operation",
				     json_object_new_string("register")));
	CKINT(json_object_object_add(entry, "certificateRequest",
		json_object_new_string(
			req_details->certificateRequest ? "yes" : "no" )));
	CKINT(json_object_object_add(entry, "debugRequest",
		json_object_new_string(
			req_details->debugRequest ? "yes" : "no" )));
	CKINT(json_object_object_add(entry, "production",
		json_object_new_string(
			req_details->production ? "yes" : "no" )));
	CKINT(json_object_object_add(entry, "encryptAtRest",
		json_object_new_string(
			req_details->encryptAtRest ? "yes" : "no" )));

	algorithms = json_object_new_array();
	CKNULL(algorithms, -ENOMEM);
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "New algorithms array\n");
	for (i = 0; i < def->num_algos; i++)
		CKINT(acvp_req_set_algo(algorithms, def->algos + i));

	CKINT(json_object_object_add(entry, "algorithms", algorithms));

	CKINT(json_object_array_add(request, entry));

	json_logger(LOGGER_DEBUG2, LOGGER_C_ANY, request,
		    "Request JSON object");

	return 0;

out:
	ACVP_JSON_PUT_NULL(algorithms);
	ACVP_JSON_PUT_NULL(entry);
	ACVP_JSON_PUT_NULL(tmp);
	return ret;
}

static int acvp_expected_url(char *url, uint32_t urllen)
{
	int ret;

	CKNULL_LOG(url, -EINVAL, "URL buffer missing\n");
	CKINT(acvp_extend_string(url, urllen, "/%s",
				 NIST_VAL_OP_EXPECTED_RESULTS));

out:
	return ret;
}

/*
 * Fetch data and process potential retry responses
 */
int acvp_process_retry(const struct acvp_vsid_ctx *vsid_ctx,
		       struct acvp_buf *result_data,
		       const char *url,
	int (*debug_logger)(const struct acvp_vsid_ctx *vsid_ctx,
			    const struct acvp_buf *buf, int err))
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_na_ex netinfo;
	struct json_object *resp = NULL, *data = NULL;
	uint32_t sleep_time = 0;
	int ret, ret2;

	CKNULL_LOG(auth, -EINVAL, "Authentication context missing\n");

	/* Refresh the ACVP JWT token by re-logging in. */
	CKINT(acvp_login(testid_ctx));

	if (vsid_ctx->vsid) {
		logger_status(LOGGER_C_ANY,
			      "(Re)Try testID %u / vsID %u (%u / %u done)\n",
			      testid_ctx->testid, vsid_ctx->vsid,
			      atomic_read(&glob_vsids_processed),
			      atomic_read(&glob_vsids_to_process));
	} else {
		logger_status(LOGGER_C_ANY, "(Re)Try testID %u\n",
			      testid_ctx->testid);
	}

	/*
	 * Retrieve the result.
	 * Do not use CKINT here to allow storing the server response as
	 * debug message in any case, even if there is an error.
	 */
	CKINT(acvp_get_net(&netinfo.net));
	netinfo.url = url;
	netinfo.server_auth = testid_ctx->server_auth;
	mutex_reader_lock(&auth->mutex);
	ret2 = na->acvp_http_get(&netinfo, result_data);
	mutex_reader_unlock(&auth->mutex);

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response (ret: %d): %s\n", ret,
	       (result_data->buf) ? (char *)result_data->buf : "(null)");

	/* Store the debug version of the result unconditionally. */
	if (debug_logger) {
		CKINT(debug_logger(vsid_ctx, result_data, ret2));
	}

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Strip the version array entry and get the data. */
	CKINT(acvp_req_strip_version(result_data->buf, &resp, &data));

	/* Server asked us to retry in given number of seconds */
	if (!json_get_uint(data, "retry", &sleep_time)) {
		ACVP_JSON_PUT_NULL(resp);
		acvp_free_buf(result_data);

		if (vsid_ctx->vsid) {
			logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "ACVP server requested retry - sleeping for %u seconds for vsID %u again\n",
			       sleep_time, vsid_ctx->vsid);
		} else {
			logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "ACVP server requested retry - sleeping for %u seconds for testID %u again\n",
			       sleep_time, testid_ctx->testid);
		}

		CKINT(sleep_interruptible(sleep_time, &acvp_op_interrupted));

		return acvp_process_retry(vsid_ctx, result_data, url,
					  debug_logger);
	}

out:
	if (ret)
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Failure in processing testID %u with vsID %u (%d)\n",
		       testid_ctx->testid, vsid_ctx->vsid, ret);

	ACVP_JSON_PUT_NULL(resp);
	return ret;
}

int acvp_process_retry_testid(const struct acvp_testid_ctx *testid_ctx,
			      struct acvp_buf *result_data,
			      const char *url)
{
	struct acvp_vsid_ctx vsid_ctx;

	/* Create a fake vsid_ctx so that _acvp_process_retry is happy. */
	memset(&vsid_ctx, 0, sizeof(vsid_ctx));

	vsid_ctx.testid_ctx = testid_ctx;

	return acvp_process_retry(&vsid_ctx, result_data, url, NULL);
}

/* GET /testSessions/<testSessionId>/vectorSets/<vectorSetId>/expected */
int acvp_get_testvectors_expected(const struct acvp_vsid_ctx *vsid_ctx)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	ACVP_BUFFER_INIT(buf);
	char url[ACVP_NET_URL_MAXLEN];
	int ret;

	/* Get the sample test vector if requested by caller */
	if (!req_details->request_sample)
		return 0;

	CKINT(acvp_vsid_url(vsid_ctx, url, sizeof(url)));
	CKINT(acvp_expected_url(url, sizeof(url)));
	CKINT(acvp_process_retry(vsid_ctx, &buf, url,
				 acvp_store_vector_debug));
	CKINT(ds->acvp_datastore_write_vsid(vsid_ctx, datastore->expectedfile,
					    false, &buf));

out:
	acvp_free_buf(&buf);
	return ret;
}

/* GET /testSessions/<testSessionId>/vectorSets/<vectorSetId> */
int acvp_get_testvectors(const struct acvp_vsid_ctx *vsid_ctx)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct acvp_net_ctx *net;
	ACVP_BUFFER_INIT(buf);
	ACVP_BUFFER_INIT(tmp);
	char url[ACVP_NET_URL_MAXLEN];
	int ret, ret2;

	/* Refresh the ACVP JWT token by re-logging in. */
	CKINT(acvp_login(testid_ctx));

	/* Prepare the URL to be used for downloading the vsID */
	CKINT(acvp_vsid_url(vsid_ctx, url, sizeof(url)));

	/* Do the actual download of the vsID */
	ret2 = acvp_process_retry(vsid_ctx, &buf, url,
				  acvp_store_vector_debug);

	/* Initialize the vsID directory for later potential re-load. */
	CKINT(acvp_store_vector_status(vsid_ctx,
				       "vsID HTTP GET operation completed with return code %d\n",
				       ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Store the vsID data in data store */
	CKINT(ds->acvp_datastore_write_vsid(vsid_ctx, datastore->vectorfile,
					    false, &buf));

	CKINT(acvp_get_net(&net));
	tmp.buf = (uint8_t *)net->server_name;
	tmp.len = strlen((char *)tmp.buf);
	CKINT(ds->acvp_datastore_write_vsid(vsid_ctx, datastore->srcserver,
					    true, &tmp));

	CKINT(acvp_get_testvectors_expected(vsid_ctx));

	/* Unconstify allowed as we operate on an atomic primitive. */
	atomic_inc((atomic_t *)&testid_ctx->vsids_processed);
	atomic_inc(&glob_vsids_processed);

	logger_status(LOGGER_C_ANY,
		      "Tests obtained for testID %u / vsID %u (%u / %u done)\n",
		      testid_ctx->testid, vsid_ctx->vsid,
		      atomic_read(&glob_vsids_processed),
		      atomic_read(&glob_vsids_to_process));

out:
	acvp_free_buf(&buf);
	return ret;
}

void acvp_record_vsid_duration(const struct acvp_vsid_ctx *vsid_ctx,
			       const char *pathname)
{
	ACVP_BUFFER_INIT(buf);
	char string[16];

	if (!vsid_ctx->start.tv_sec && !vsid_ctx->start.tv_nsec)
		return;

	/* Store the time the network communication took */
	duration_string(&vsid_ctx->start, string, sizeof(string));
	buf.buf = (uint8_t *)string;
	buf.len = strlen(string);

	/*
	 * We deliberately do not catch the return code as this is a status
	 * log information only. Hence, in case this write fails, do not worry.
	 */
	ds->acvp_datastore_write_vsid(vsid_ctx, pathname, false, &buf);
}

#ifdef ACVP_USE_PTHREAD
static int acvp_process_req_thread(void *arg)
{
	struct acvp_thread_ctx *tdata = (struct acvp_thread_ctx *)arg;
	struct acvp_vsid_ctx *vsid_ctx = tdata->vsid_ctx;
	int ret;

	free(tdata);

	ret = acvp_get_testvectors(vsid_ctx);

	/* Store the time the download took */
	acvp_record_vsid_duration(vsid_ctx, ACVP_DS_DOWNLOADDURATION);

	acvp_release_vsid_ctx(vsid_ctx);

	return ret;
}
#endif

struct acvp_vsid_array {
	uint32_t entries;
	uint32_t *vsids;
	const char **urls;
};

static int acvp_get_vsid_array(struct json_object *response,
			       struct acvp_vsid_array *array)
{
	struct json_object *vectorsets;
	unsigned int i;
	int ret;

	CKINT(json_find_key(response, "vectorSetUrls", &vectorsets,
			    json_type_array));

	array->entries = (uint32_t)json_object_array_length(vectorsets);
	array->vsids = calloc(1, sizeof(uint32_t) * array->entries);
	CKNULL(array->vsids, -ENOMEM);

	array->urls = calloc(1, sizeof(char *) * array->entries);
	CKNULL(array->urls, -ENOMEM);

	for (i = 0; i < array->entries; i++) {
		struct json_object *vsid_url =
				json_object_array_get_idx(vectorsets, i);

		if (!json_object_is_type(vsid_url, json_type_string)) {
			json_logger(LOGGER_WARN, LOGGER_C_ANY, vsid_url,
				    "JSON value is no string");
			ret = -EINVAL;
			goto out;
		}

		array->urls[i] = json_object_get_string(vsid_url);
		CKINT(acvp_get_trailing_number(array->urls[i],
					       &(array->vsids[i])));

		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Received vsID URL %s (parsed vsID: %u)\n",
		       array->urls[i], array->vsids[i]);
	}

out:
	if (ret) {
		if (array->vsids) {
			free(array->vsids);
			array->vsids = NULL;
		}
		if (array->urls) {
			free(array->urls);
			array->urls = NULL;
		}
		array->entries = 0;
	}

	return ret;
}

static int acvp_process_vectors(struct acvp_testid_ctx *testid_ctx,
				struct json_object *entry)
{
	struct acvp_vsid_array vsid_array = { 0, NULL, NULL };
	unsigned int i;
	int ret;

	if (!entry) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	/* Get an array of vsIDs that are ready for download */
	CKINT(acvp_get_vsid_array(entry, &vsid_array));

	/* Iterate over all vsIDs and store status in the data store */
	for (i = 0; i < vsid_array.entries; i++) {
		struct acvp_vsid_ctx vsid_ctx;

		vsid_ctx.testid_ctx = testid_ctx;
		vsid_ctx.vsid = vsid_array.vsids[i];

		/* Initialize the vsID directory for later potential re-load. */
		CKINT(acvp_store_vector_status(&vsid_ctx,
					       "vsID downloading commences\n"));

		atomic_inc(&testid_ctx->vsids_to_process);
		atomic_inc(&glob_vsids_to_process);
	}

	/* Iterate over all vsID and download each */
	for (i = 0; i < vsid_array.entries; i++) {
		struct acvp_vsid_ctx *vsid_ctx;

		vsid_ctx = calloc(1, sizeof(*vsid_ctx));
		CKNULL(vsid_ctx, -ENOMEM);
		vsid_ctx->testid_ctx = testid_ctx;
		vsid_ctx->vsid = vsid_array.vsids[i];
		if (clock_gettime(CLOCK_REALTIME, &vsid_ctx->start)) {
			ret = -errno;
			acvp_release_vsid_ctx(vsid_ctx);
			goto out;
		}

		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Fetching data for vsID %u\n",
		       vsid_ctx->vsid);

#ifdef ACVP_USE_PTHREAD
		/* Disable threading in DEBUG mode */
		if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_DEBUG) {
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "Disable threading support\n");
			ret = acvp_get_testvectors(vsid_ctx);
			acvp_release_vsid_ctx(vsid_ctx);
			if (ret)
				goto out;
		} else {
			struct acvp_thread_ctx *tdata;
			int ret_ancestor;

			tdata = calloc(1, sizeof(*tdata));
			if (!tdata) {
				acvp_release_vsid_ctx(vsid_ctx);
				ret = -ENOMEM;
				goto out;
			}
			tdata->vsid_ctx = vsid_ctx;
			CKINT(thread_start(acvp_process_req_thread, tdata, 1,
					   &ret_ancestor));
			ret |= ret_ancestor;
		}
#else
		ret = acvp_get_testvectors(vsid_ctx);
		acvp_release_vsid_ctx(vsid_ctx);
		if (ret)
			goto out;
#endif
	}

out:
	if (vsid_array.vsids)
		free(vsid_array.vsids);
	if (vsid_array.urls)
		free(vsid_array.urls);

#ifdef ACVP_USE_PTHREAD
	ret |= thread_wait();
#endif

	return ret;
}

#if 0
/* GET /testSessions/<testSessionId>/vectorSets */
static int acvp_get_vectors(struct acvp_testid_ctx *testid_ctx)
{
	ACVP_BUFFER_INIT(response_buf);
	int ret, ret2;
	char url[ACVP_NET_URL_MAXLEN];

	CKINT(acvp_vectorset_url(testid_ctx, url, sizeof(url)));

	ret2 = _acvp_process_retry_testid(testid_ctx, &response_buf, url);

	if (!response_buf.buf || !response_buf.len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response: %s\n", response_buf.buf);

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_vector_request_debug(testid_ctx, &response_buf,
					      ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Process the response and download the vectors. */
	CKINT(acvp_process_vectors(testid_ctx, &response_buf));

out:
	acvp_free_buf(&response_buf);
	return ret;
}
#endif

static int acvp_register_dump_request(struct acvp_testid_ctx *testid_ctx,
				      struct json_object *request)
{
	struct tm now_detail;
	time_t now;
	ACVP_BUFFER_INIT(register_buf);
	char filename[40];
	const char *json_request;
	int ret;

	now = time(NULL);
	if (now == (time_t)-1) {
		ret = -errno;
		logger(LOGGER_WARN, LOGGER_C_ANY, "Cannot obtain local time\n");
		return ret;
	}
	localtime_r(&now, &now_detail);

	snprintf(filename, sizeof(filename),
		 "%s-%d%.2d%.2d_%.2d-%.2d-%.2d.json",
		 ACVP_DS_DEF_REQUEST,
		 now_detail.tm_year + 1900,
		 now_detail.tm_mon + 1,
		 now_detail.tm_mday,
		 now_detail.tm_hour,
		 now_detail.tm_min,
		 now_detail.tm_sec);

	json_request = json_object_to_json_string_ext(request,
					JSON_C_TO_STRING_PRETTY  |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = strlen(json_request);
	CKINT(ds->acvp_datastore_write_testid(testid_ctx, filename,
					      true, &register_buf));

out:
	return ret;
}

static int acvp_get_testid(struct acvp_testid_ctx *testid_ctx,
			   struct json_object *request,
			   struct json_object *register_response)
{
	int ret;
	char *str;

	/* We know we are not modifying str, so constify is ok here */
	CKINT(json_get_string(register_response, "url", (const char **)&str));

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Received testID URL: %s\n", str);

	CKINT(acvp_get_trailing_number(str, &testid_ctx->testid));

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Received testID: %u\n",
	       testid_ctx->testid);

	/* Write test request */
	CKINT(acvp_register_dump_request(testid_ctx, request));

out:
	return ret;
}

static int acvp_process_req(struct acvp_testid_ctx *testid_ctx,
			    struct json_object *request,
			    struct acvp_buf *response)
{
	struct json_object *req = NULL, *entry = NULL;
	const char *jwt;
	int ret;

	if (!response->buf || !response->len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response: %s\n", response->buf);

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(response->buf, &req, &entry));

	/* Extract testID URL and ID number */
	CKINT(acvp_get_testid(testid_ctx, request, entry));

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(testid_ctx, ACVP_DS_TESTIDMETA,
					      true, response));

	/* Store the definition search criteria */
	CKINT(acvp_export_def_search(testid_ctx));

	/* Get access token */
	CKINT(json_get_string(entry, "accessToken", &jwt));

	/* Store access token in ctx */
	CKINT(acvp_set_authtoken(testid_ctx, jwt));

	/* Download the testvectors */
	CKINT(acvp_process_vectors(testid_ctx, entry));

out:
	ACVP_JSON_PUT_NULL(req);

	return ret;
}

/* POST /testSessions */
static int acvp_register_op(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	struct acvp_na_ex netinfo;
	struct json_object *request = NULL;
	ACVP_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKINT(acvp_init_auth(testid_ctx));

	request = json_object_new_array();
	CKNULL(request, -ENOMEM);

	/* Construct the registration message. */
	CKINT(acvp_req_build(testid_ctx, request));

	if (!req_details->dump_register)
		sig_enqueue_ctx(testid_ctx);

	/* Log into the ACVP server using the TOTP authentication */
	CKINT(acvp_login(testid_ctx));

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(request,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(request,
					JSON_C_TO_STRING_PLAIN  |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = strlen(json_request);

	CKINT(acvp_create_url(NIST_VAL_OP_REG, url, sizeof(url)));

	/* Send the capabilities to the ACVP server. */
	CKINT(acvp_get_net(&netinfo.net));
	netinfo.url = url;
	netinfo.server_auth = testid_ctx->server_auth;
	mutex_reader_lock(&testid_ctx->server_auth->mutex);
	ret2 = na->acvp_http_post(&netinfo, &register_buf, &response_buf);
	mutex_reader_unlock(&testid_ctx->server_auth->mutex);

	if (!response_buf.buf || !response_buf.len) {
		ret = -ENODATA;
		goto out;
	}

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response: %s\n", response_buf.buf);

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Process the response and download the vectors. */
	CKINT(acvp_process_req(testid_ctx, request, &response_buf));

out:
	if (!req_details->dump_register)
		sig_dequeue_ctx(testid_ctx);

	if (ret && testid_ctx)
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Failure to submit testID %u\n",
		       testid_ctx->testid);

	acvp_release_auth(testid_ctx);
	testid_ctx->server_auth = NULL;
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response_buf);

	return ret;
}

void acvp_record_testid_duration(const struct acvp_testid_ctx *testid_ctx,
				 const char *pathname)
{
	ACVP_BUFFER_INIT(buf);
	char string[16];

	if (!testid_ctx->start.tv_sec && !testid_ctx->start.tv_nsec)
		return;

	/* Store the time the network operation took */
	duration_string(&testid_ctx->start, string, sizeof(string));
	buf.buf = (uint8_t *)string;
	buf.len = strlen(string);

	/*
	 * We deliberately do not catch the return code as this is a status
	 * log information only. Hence, in case this write fails, do not worry.
	 */
	ds->acvp_datastore_write_testid(testid_ctx, pathname, false, &buf);
}

static int _acvp_register(const struct acvp_ctx *ctx,
			  const struct definition *def)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	int ret;

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;
	testid_ctx->sig_cancel_send_delete = true;
	atomic_set(0, &testid_ctx->vsids_to_process);
	atomic_set(0, &testid_ctx->vsids_processed);

	if (clock_gettime(CLOCK_REALTIME, &testid_ctx->start)) {
		ret = -errno;
		goto out;
	}

	logger_status(LOGGER_C_ANY, "Register module %s\n",
		      def->info->module_name);
	CKINT(acvp_register_op(testid_ctx));

out:
	if (atomic_read(&testid_ctx->vsids_processed) <
	    atomic_read(&testid_ctx->vsids_to_process)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Not all test vectors obtained for testID %u (%u missing) - use options --testid %u --request to retry fetching them\n",
		       testid_ctx->testid,
		       atomic_read(&testid_ctx->vsids_to_process) -
		       atomic_read(&testid_ctx->vsids_processed),
		       testid_ctx->testid);

		acvp_record_failed_testid(testid_ctx->testid);
	} else {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "All vsIDs processed for testID %u\n",
		       testid_ctx->testid);
	}

	if (!req_details->dump_register &&
	    atomic_read(&testid_ctx->vsids_to_process)) {
		acvp_record_testid_duration(testid_ctx,
					    ACVP_DS_DOWNLOADDURATION);
	}

	acvp_release_testid(testid_ctx);

	return ret;
}


#ifdef ACVP_USE_PTHREAD
static int acvp_register_thread(void *arg)
{
	struct acvp_thread_reqresp_ctx *tdata = arg;
	const struct acvp_ctx *ctx = tdata->ctx;
	const struct definition *def = tdata->def;

	free(tdata);

	return _acvp_register(ctx, def);
}
#endif

DSO_PUBLIC
int acvp_register(const struct acvp_ctx *ctx)
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	struct definition *def;
	int ret;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "ACVP library was not yet initialized\n");
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
#ifdef ACVP_USE_PTHREAD
		/* Disable threading in DEBUG mode */
		if (logger_get_verbosity(LOGGER_C_ANY) >= LOGGER_DEBUG) {
			logger(LOGGER_DEBUG, LOGGER_C_ANY,
			       "Disable threading support\n");
			CKINT(_acvp_register(ctx, def));
		} else {
			struct acvp_thread_reqresp_ctx *tdata;
			int ret_ancestor;

			tdata = calloc(1, sizeof(*tdata));
			CKNULL(tdata, -ENOMEM);
			tdata->ctx = ctx;
			tdata->def = def;
			ret = thread_start(acvp_register_thread, tdata, 0,
					   &ret_ancestor);
			if (ret) {
				free(tdata);
				goto out;
			}

			ret |= ret_ancestor;
		}
#else
		CKINT(_acvp_register(ctx, def));
#endif


		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

out:

#ifdef ACVP_USE_PTHREAD
	ret |= thread_wait();
#endif

	return ret;
}
