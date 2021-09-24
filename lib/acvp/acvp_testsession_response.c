/* ACVP proxy protocol handler for submitting test responses
 *
 * Copyright (C) 2018 - 2021, Stephan Mueller <smueller@chronox.de>
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

#include "acvp_error_handler.h"
#include "logger.h"
#include "acvpproxy.h"
#include "json_wrapper.h"
#include "internal.h"
#include "request_helper.h"
#include "sleep.h"
#include "term_colors.h"
#include "threading_support.h"

/*
 * The support for the large endpoint is deactivated on the server. We leave
 * the code for the time being to remove it later.
 */
#undef ACVP_LARGE_ENDPOINT

static int acvp_vsid_verdict_url(const struct acvp_vsid_ctx *vsid_ctx,
				 char *url, const uint32_t urllen,
				 const bool urlpath)
{
	int ret;

	CKINT(acvp_vsid_url(vsid_ctx, url, urllen, urlpath));
	CKINT(acvp_extend_string(url, urllen, "/%s", NIST_VAL_OP_RESULTS));

out:
	return ret;
}

static int acvp_testid_verdict_url(const struct acvp_testid_ctx *testid_ctx,
				   char *url, const uint32_t urllen,
				   const bool urlpath)
{
	int ret;

	CKINT(acvp_testid_url(testid_ctx, url, urllen, urlpath));
	CKINT(acvp_extend_string(url, urllen, "/%s", NIST_VAL_OP_RESULTS));

out:
	return ret;
}

int acvp_init_testid_ctx(struct acvp_testid_ctx *testid_ctx,
			 const struct acvp_ctx *ctx,
			 const struct definition *def, const uint32_t testid)
{
	int ret = 0;

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;
	testid_ctx->testid = testid;
	atomic_set(0, &testid_ctx->vsids_to_process);
	atomic_set(0, &testid_ctx->vsids_processed);

	if (clock_gettime(CLOCK_REALTIME, &testid_ctx->start)) {
		ret = -errno;
		goto out;
	}

out:
	return ret;
}

#ifdef ACVP_LARGE_ENDPOINT
static int acvp_copy_vsid_ctx(struct acvp_vsid_ctx *dst,
			      const struct acvp_vsid_ctx *src)
{
	/*
	 * We only copy the main structure, and do NOT duplicate the testID
	 * ctx.
	 */
	memcpy(dst, src, sizeof(*dst));
	return 0;
}

static int acvp_copy_testid_ctx(struct acvp_testid_ctx *dst,
				const struct acvp_testid_ctx *src)
{
	int ret;

	CKINT(acvp_init_testid_ctx(dst, src->ctx, src->def, src->testid));

out:
	return ret;
}
#endif

/*****************************************************************************
 * Remember the test verdicts of the vsIDs
 *****************************************************************************/
#define ACVP_VERDICT_MAX 512
static uint32_t acvp_verdict[2][ACVP_VERDICT_MAX];
static atomic_t acvp_verdict_ptr[2] = { ATOMIC_INIT(-1), ATOMIC_INIT(-1) };

static void acvp_record_verdict_vsid(const uint32_t vsid, const bool passed)
{
	int idx = atomic_inc(&acvp_verdict_ptr[passed]);

	if (idx < 0 || idx >= ACVP_VERDICT_MAX) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Cannot track verdict vsID %u for %s verdicts\n", vsid,
		       passed ? "passed" : "failed");
		return;
	}

	acvp_verdict[passed][idx] = vsid;
}

DSO_PUBLIC
int acvp_list_verdict_vsid(int *idx_ptr, uint32_t *vsid, const bool passed)
{
	int idx = atomic_read(&acvp_verdict_ptr[passed]);

	if (*idx_ptr > idx)
		return -ENOENT;

	idx = *idx_ptr;

	if (idx < 0 || idx >= ACVP_VERDICT_MAX)
		return -ENOENT;

	*vsid = acvp_verdict[passed][idx];
	*idx_ptr = *idx_ptr + 1;

	return 0;
}

/*****************************************************************************
 * Code for submitting test results and fetching the verdicts
 *****************************************************************************/
static int acvp_check_verdict(const struct acvp_vsid_ctx *vsid_ctx,
			      const struct acvp_buf *verdict_buf,
			      enum acvp_test_verdict *verdict_stat)
{
	int ret;

	CKINT(acvp_get_verdict_json(verdict_buf, verdict_stat));

	acvp_record_verdict_vsid(vsid_ctx->vsid,
				 (*verdict_stat == acvp_verdict_pass));

out:
	return ret;
}

/* GET /testSessions/<testSessionId>/vectorSets/<vectorSetId>/results */
static int acvp_get_vsid_verdict(const struct acvp_vsid_ctx *vsid_ctx)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	ACVP_BUFFER_INIT(result);
	enum acvp_test_verdict verdict_stat;
	char url[ACVP_NET_URL_MAXLEN];
	int ret;

	/*
	 * Construct the URL to get the server's response (i.e. final verdict)
	 * for the given results.
	 */
	CKINT(acvp_vsid_verdict_url(vsid_ctx, url, sizeof(url), false));
	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Retrieve test results from URL %s\n", url);

	/* Submit request and prepare for a retry reply. */
	CKINT(acvp_process_retry(vsid_ctx, &result, url,
				 acvp_store_verdict_debug));

	/* Store the entire received response. */
	if (result.buf && result.len)
		CKINT(ds->acvp_datastore_write_vsid(
			vsid_ctx, datastore->verdictfile, false, &result));

	/* Unconstify allowed as we operate on an atomic primitive. */
	atomic_inc((atomic_t *)&testid_ctx->vsids_processed);
	atomic_inc(&glob_vsids_processed);

	/*
	 * Get the global verdict for the vsID to allow it to be listed
	 * to the user.
	 */
	ret = acvp_check_verdict(vsid_ctx, &result, &verdict_stat);
	if (ret) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Verdict verification failed for vsID %u\n",
		       vsid_ctx->vsid);
	}

	logger_status(
		LOGGER_C_ANY,
		"Verdict obtained for testID %u / vsID %u (completed vsIDs %u / %u) - %s%s%s\n",
		testid_ctx->testid, vsid_ctx->vsid,
		atomic_read(&glob_vsids_processed),
		atomic_read(&glob_vsids_to_process),
		(verdict_stat == acvp_verdict_pass) ? TERM_COLOR_GREEN :
							    TERM_COLOR_RED,
		(verdict_stat == acvp_verdict_pass) ? "PASSED" : "FAILED",
		TERM_COLOR_NORMAL);

	/* Ensure that testID verdict is re-downloaded */
	ret = EAGAIN;

out:
	acvp_free_buf(&result);
	return ret;
}

/* Process any return code from the ACVP server */
static int acvp_response_error_handler(const int request_ret)
{
	enum acvp_error_code code;

	if (request_ret <= 0)
		return request_ret;

	code = (enum acvp_error_code)request_ret;

	switch (code) {
	case ACVP_ERR_RESPONSE_RECEIVED_VERDICT_PENDING:
		/*
		 * Vectors were uploaded, we clear the error to allow
		 * downloading of verdict.
		 */
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "ACVP server already received responses, continuing to obtain verdict\n");
		return 0;

	case ACVP_ERR_NO_ERR:
	case ACVP_ERR_RESPONSE_REJECTED:
	case ACVP_ERR_AUTH_JWT_EXPIRED:
	default:
		return -request_ret;
	}
}

/* POST, PUT /testSessions/<testSessionId>/vectorSets/<vectorSetId>/results */
static int acvp_response_upload(const struct acvp_vsid_ctx *vsid_ctx,
				const struct acvp_ext_buf *buf, const char *url)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	ACVP_BUFFER_INIT(result);
	enum acvp_http_type nettype = acvp_http_post;
	int ret, ret2;

	CKNULL_LOG(url, -EFAULT, "URL missing\n");

	if (opts->resubmit_result)
		nettype = acvp_http_put;
	ret2 = acvp_net_op(testid_ctx, url, buf, &result, nettype);

	CKINT(acvp_store_submit_debug(vsid_ctx, &result, ret2));

	CKINT(acvp_response_error_handler(ret2));

out:
	if (ret)
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Failure to submit testID %u with vsID %u\n",
		       testid_ctx->testid, vsid_ctx->vsid);
	acvp_free_buf(&result);
	return ret;
}

/* DELETE /testSessions/<testSessionId>/vectorSets/<vectorSetId> */
static int acvp_response_delete(const struct acvp_vsid_ctx *vsid_ctx)
{
#define ACVP_RESPONSE_DELETE_SLEEP_TIME 30
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	char url[ACVP_NET_URL_MAXLEN];
	int ret;

	CKINT(acvp_vsid_url(vsid_ctx, url, sizeof(url), false));
	CKINT(acvp_net_op(testid_ctx, url, NULL, NULL, acvp_http_delete));
	logger_status(
		LOGGER_C_ANY,
		"VsID %u (test session %u) invalidated - sleeping for %u seconds to allow ACVP server propagation\n",
		vsid_ctx->vsid, testid_ctx->testid,
		ACVP_RESPONSE_DELETE_SLEEP_TIME);

	/*
	 * As we re-download the testID verdict, we need to sleep
	 * to allow the propagation of the deletion operation through
	 * the ACVP server.
	 */
	CKINT(sleep_interruptible(ACVP_RESPONSE_DELETE_SLEEP_TIME,
				  &acvp_op_interrupted));

out:
	return ret;
}

#ifdef ACVP_LARGE_ENDPOINT
/* POST /large */
static int acvp_get_large_endpoint(const struct acvp_vsid_ctx *vsid_ctx,
				   const struct acvp_buf *submit_buf,
				   struct acvp_buf *received_buf)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	struct json_object *entry = NULL, *large = NULL;
	ACVP_BUFFER_INIT(large_req_buf);
	int ret;
	char url[ACVP_NET_URL_MAXLEN], urlpath[ACVP_NET_URL_MAXLEN];
	const char *json_large;

	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Sending response to large endpoint\n");
	CKINT(acvp_create_url(NIST_VAL_OP_LARGE, url, sizeof(url)));

	/* Large request to be send */
	large = json_object_new_array();
	CKNULL(large, -ENOMEM);

	CKINT(acvp_req_add_version(large));

	entry = json_object_new_object();
	CKNULL(entry, ENOMEM);

	CKINT(json_object_object_add(entry, "submissionSize",
				     json_object_new_int((int)submit_buf->len)));

	CKINT(acvp_vsid_url(vsid_ctx, urlpath, sizeof(urlpath), true));
	CKINT(json_object_object_add(entry, "vectorSetUrl",
				     json_object_new_string(urlpath)));

	CKINT(json_object_array_add(large, entry));
	entry = NULL;

	/* Convert the JSON buffer into a string */
	json_large = json_object_to_json_string_ext(
		large, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_large, -EFAULT,
		   "JSON object conversion into string failed\n");

	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
	       "Requesting large endpoint for data size %u\n", submit_buf->len);

	large_req_buf.buf = (uint8_t *)json_large;
	large_req_buf.len = (uint32_t)strlen(json_large);

	CKINT(acvp_net_op(testid_ctx, url, &large_req_buf, received_buf,
			  acvp_http_post));

out:
	ACVP_JSON_PUT_NULL(large);
	ACVP_JSON_PUT_NULL(entry);
	return ret;
}

/* POST to large endpoint */
static int acvp_submit_large_endpoint(const struct acvp_vsid_ctx *vsid_ctx,
				      const struct acvp_buf *large_endpoint,
				      const struct acvp_buf *submit_buf)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct json_object *req = NULL, *entry = NULL;
	struct acvp_testid_ctx tmptestid_ctx;
	struct acvp_vsid_ctx tmpvsid_ctx;
	int ret;
	const char *str;

	/*
	 * We may get a new temporary authtoken for just this one /large
	 * communication endpoint. For handling this authtoken, we need
	 * to create a new vsID and testID context to keep the one-off
	 * authtoken local to this one request.
	 */
	memset(&tmptestid_ctx, 0, sizeof(tmptestid_ctx));
	/* Prepare a temporary context to hold the temporary auth token */
	CKINT(acvp_copy_testid_ctx(&tmptestid_ctx, testid_ctx));
	CKINT(acvp_init_auth(&tmptestid_ctx));
	CKINT(acvp_copy_auth(tmptestid_ctx.server_auth, auth));
	auth = tmptestid_ctx.server_auth;
	CKINT(acvp_copy_vsid_ctx(&tmpvsid_ctx, vsid_ctx));
	/* Set the temp testID context with the temp authtoken */
	tmpvsid_ctx.testid_ctx = &tmptestid_ctx;

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(large_endpoint, &req, &entry));

	/*
	 * Get new access token if exists - we ignore any error as the
	 * accessToken is optional at this point. Locking is not really needed
	 * as we have a private authtoken. Yet, it remains to prevent future
	 * bugs in case this authtoken may be shared among threads. Our current
	 * locks hardly have any performance impacts.
	 */
	mutex_lock(&auth->mutex);
	acvp_get_accesstoken(&tmptestid_ctx, entry, false);
	mutex_unlock(&auth->mutex);

	/* We know we are not modifying str, so constify is ok here */
	CKINT(json_get_string(entry, "url", (const char **)&str));
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Received large endpoint URI: %s\n",
	       str);

	//WARNING: we use the URL from the server verbatim without checking!
	CKINT(acvp_response_upload(&tmpvsid_ctx, submit_buf, str));

out:
	acvp_release_auth(&tmptestid_ctx);
	ACVP_JSON_PUT_NULL(req);
	return ret;
}
#endif

static int acvp_check_large_endpoint(const struct acvp_vsid_ctx *vsid_ctx,
				     const struct acvp_ext_buf *submit_buf)
{
	ACVP_BUFFER_INIT(received_buf);
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

#ifdef ACVP_LARGE_ENDPOINT
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	uint32_t max_msg_size;
	CKINT(acvp_get_max_msg_size(testid_ctx, &max_msg_size));

	/* Check whether we need to request a /large endpoint communication */
	if (!submit_buf || max_msg_size >= submit_buf->len) {
#endif
		/*
		 * Construct the URL to submit the results for the given
		 * vsID to.
		 */
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Sending response to regular endpoint\n");
		CKINT(acvp_vsid_verdict_url(vsid_ctx, url, sizeof(url), false));
		return acvp_response_upload(vsid_ctx, submit_buf, url);
#ifdef ACVP_LARGE_ENDPOINT
	}

	CKINT(acvp_get_large_endpoint(vsid_ctx, submit_buf, &received_buf));

	CKINT(acvp_submit_large_endpoint(vsid_ctx, &received_buf, submit_buf));
#endif

out:
	acvp_free_buf(&received_buf);
	return ret;
}

static int acvp_request_sample_vsid(const struct acvp_vsid_ctx *vsid_ctx,
				    const struct acvp_ext_buf *buf)
{
	struct json_object *full = NULL, *response;
	const char *new_str;
	ACVP_BUFFER_INIT(tmp_buf);
	ACVP_EXT_BUFFER_INIT(new_buf);
	int ret;

	tmp_buf.buf = buf->buf;
	tmp_buf.len = buf->len;
	CKINT_LOG(acvp_req_strip_version(&tmp_buf, &full, &response),
		  "Cannot parse response data %s\n", buf->buf);
	CKINT(json_object_object_add(response, "showExpected",
				     json_object_new_boolean(true)));

	new_str = json_object_to_json_string_ext(
		full, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL(new_str, -EFAULT);
	new_buf.buf = (uint8_t *)new_str;
	new_buf.len = (uint32_t)strlen(new_str);

	CKINT(acvp_check_large_endpoint(vsid_ctx, &new_buf));

out:
	ACVP_JSON_PUT_NULL(full);
	return ret;
}

static int acvp_response_submit_one(const struct acvp_vsid_ctx *vsid_ctx,
				    const struct acvp_ext_buf *buf)
{
	const struct acvp_testid_ctx *testid_ctx = vsid_ctx->testid_ctx;
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	const struct acvp_req_ctx *req = &ctx->req_details;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	const struct acvp_net_ctx *net;
	ACVP_BUFFER_INIT(tmp);
	int ret;

	CKINT(acvp_get_net(&net));

	tmp.buf = (uint8_t *)net->server_name;
	tmp.len = (uint32_t)strlen((char *)tmp.buf);
	ret = ds->acvp_datastore_compare(vsid_ctx, datastore->srcserver, true,
					 true, &tmp);
	if (ret < 0) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Could not match the upload server for vsID %u with the download server\n",
		       vsid_ctx->vsid);
		goto out;
	}

	/*
	 * The server which we used for downloading the vector is not the
	 * same as for uploading.
	 *
	 * This check implicitly enforces that when test vectors are downloaded
	 * from the demo/debug ACVP server, the vectors cannot be uploaded to
	 * the production ACVP server and vice versa.
	 */
	if (!ret) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "vsID %u was downloaded from a different server than it shall be uploaded to (%s)\n",
		       vsid_ctx->vsid, net->server_name);
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* macOS key chain has precedence as defined in getClientCredential */
	tmp.buf = NULL;
	tmp.len = 0;
	CKINT(acvp_cert_ref(&tmp));
	ret = ds->acvp_datastore_compare(vsid_ctx, datastore->jwtcertref, true,
					 false, &tmp);
	acvp_free_buf(&tmp);
	if (ret == 0) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Certificate used for downloading the data for vsID %u does not match current certificate!\n",
		       vsid_ctx->vsid);
		ret = -ENODATA;
		goto out;
	}
	/* we ignore all other errors as this check is a convenience feature */
	ret = 0;

	/*
	 * Only upload test results if not already done so or explicitly
	 * requested by user.
	 */
	if (!vsid_ctx->verdict_file_present || opts->resubmit_result) {
		if (req->request_sample) {
			CKINT(acvp_request_sample_vsid(vsid_ctx, buf));
		} else {
			CKINT(acvp_check_large_endpoint(vsid_ctx, buf));
		}
	}

	if (opts->upload_only) {
		/* Unconstify allowed as we operate on an atomic primitive. */
		atomic_inc((atomic_t *)&testid_ctx->vsids_processed);
		atomic_inc(&glob_vsids_processed);

		logger_status(
			LOGGER_C_ANY,
			"Test response uploaded for testID %u / vsID %u (completed vsIDs %u / %u)\n",
			testid_ctx->testid, vsid_ctx->vsid,
			atomic_read(&glob_vsids_processed),
			atomic_read(&glob_vsids_to_process));

		goto out;
	}

	CKINT(acvp_get_vsid_verdict(vsid_ctx));

out:
	return ret;
}

static int acvp_process_one_vsid(const struct acvp_vsid_ctx *vsid_ctx,
				 const struct acvp_buf *buf)
{
	const struct acvp_testid_ctx *testid_ctx;
	const struct acvp_ctx *ctx;
	const struct acvp_req_ctx *req;
	const struct acvp_opts_ctx *opts;
	ACVP_EXT_BUFFER_INIT(tmp_buf);
	int ret;

	CKNULL_LOG(vsid_ctx, -EINVAL, "ACVP vsID request context missing\n");
	testid_ctx = vsid_ctx->testid_ctx;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP testID request context missing\n");

	/* The data store tells us to only fetch the verdict. */
	if (vsid_ctx->fetch_verdict) {
		/* Unconstify allowed as we operate on an atomic primitive. */
		atomic_inc((atomic_t *)&testid_ctx->vsids_to_process);
		atomic_inc(&glob_vsids_to_process);
		return acvp_get_vsid_verdict(vsid_ctx);
	}

	ctx = testid_ctx->ctx;
	req = &ctx->req_details;
	opts = &ctx->options;

	/*
	 * There is a request to delete a vsID. Let us honor it.
	 */
	if (opts->delete_vsid) {
		atomic_inc((atomic_t *)&testid_ctx->vsids_to_process);
		atomic_inc(&glob_vsids_to_process);
		return acvp_response_delete(vsid_ctx);
	}

	if (!buf) {
		/*
		 * We are requested to download pending vsIDs.
		 */
		if (req->download_pending_vsid &&
		    !vsid_ctx->vector_file_present) {
			/*
			 * Unconstify allowed as we operate on an atomic
			 * primitive.
			 */
			atomic_inc((atomic_t *)&testid_ctx->vsids_to_process);
			atomic_inc(&glob_vsids_to_process);

			CKINT(acvp_get_testvectors(vsid_ctx));

			/* Store the time the download took */
			acvp_record_vsid_duration(vsid_ctx,
						  ACVP_DS_DOWNLOADDURATION);

			/*
			 * Indicate to the caller that the connection was
			 * restarted. Use positive integer as this is no error.
			 */
			return EINTR;
		} else {
			CKINT(acvp_get_testvectors_expected(vsid_ctx));

			/*
			 * If no buffer was provided, we do not process
			 * anything. Yet we do not return an error, because
			 * the data store backend may find other responses to
			 * submit.
			 */
			return EINTR;
		}
	}
	/*
	 * If we are requested to only download pending vsIDs, do not submit
	 * anything, but possibly we have to download expected results.
	 */
	if (req->download_pending_vsid)
		return acvp_get_testvectors_expected(vsid_ctx);

	/* Unconstify allowed as we operate on an atomic primitive. */
	atomic_inc((atomic_t *)&testid_ctx->vsids_to_process);
	atomic_inc(&glob_vsids_to_process);

	tmp_buf.buf = buf->buf;
	tmp_buf.len = buf->len;
	ret = acvp_response_submit_one(vsid_ctx, &tmp_buf);

	/* Store the time the upload took */
	acvp_record_vsid_duration(vsid_ctx, ACVP_DS_UPLOADDURATION);

out:
	return ret;
}

static int acvp_respond_testid(struct acvp_testid_ctx *testid_ctx)
{
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP volatile request context missing\n");

	CKINT(acvp_init_auth(testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/*
	 * We try to fetch open requests, but ignore the return code as at this
	 * point, we do not actively handle meta data.
	 */
	acvp_handle_open_requests(testid_ctx);

	sig_enqueue_ctx(testid_ctx);

	CKINT(ds->acvp_datastore_find_responses(testid_ctx,
						acvp_process_one_vsid));

out:
	sig_dequeue_ctx(testid_ctx);
	acvp_release_auth(testid_ctx);

	return ret;
}

/*
 * This function performs the network operation assuming testid_ctx is fully
 * initialized.
 */
/* GET /testSessions/<testSessionId>/results */
static int acvp_get_testid_verdict_request(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_datastore_ctx *datastore = &ctx->datastore;
	ACVP_BUFFER_INIT(result);
	enum acvp_test_verdict verdict_stat;
	int ret;
	char url[ACVP_NET_URL_MAXLEN];

	/*
	 * Construct the URL to get the server's response
	 * (i.e. final verdict) for the test session.
	 */
	CKINT(acvp_testid_verdict_url(testid_ctx, url, sizeof(url), false));
	logger(LOGGER_DEBUG, LOGGER_C_ANY,
	       "Retrieve test session results from URL %s\n", url);

	/* Submit request and prepare for a retry reply. */
	CKINT(acvp_process_retry_testid(testid_ctx, &result, url));

	/* Store the entire received response. */
	if (!acvp_op_get_interrupted() && result.buf && result.len) {
		CKINT(ds->acvp_datastore_write_testid(
			testid_ctx, datastore->verdictfile, false, &result));
	}

	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
	       "All test verdicts successfully obtained for testID %u\n",
	       testid_ctx->testid);

	/*
	 * Get the global verdict for the vsID to allow it to be listed
	 * to the user.
	 */
	ret = acvp_get_verdict_json(&result, &verdict_stat);
	if (ret) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Verdict verification failed for test session ID %u\n",
		       testid_ctx->testid);
	}

out:
	acvp_free_buf(&result);
	return ret;
}

/*
 * Obtain the final verdict for the test session if all test results
 * were downloaded.
 */
static int acvp_get_testid_verdict(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_opts_ctx *opts = &ctx->options;
	const struct acvp_auth_ctx *auth;
	int ret;

	if (!testid_ctx->testid)
		return 0;

	/* Force download of verdict unconditionally when vsID was deleted */
	if (!opts->delete_vsid &&
	    (atomic_read(&testid_ctx->vsids_processed) <
	     atomic_read(&testid_ctx->vsids_to_process))) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Not all test verdicts downloaded, skipping retrieval of test session verdict\n");
		return 0;
	}

	CKINT(acvp_init_auth(testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	auth = testid_ctx->server_auth;
	if (auth && auth->testsession_certificate_number) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Skipping (re-)download of verdict for test session with certificate %s\n",
		       auth->testsession_certificate_number);
		ret = 0;
		goto out;
	}

	CKINT(acvp_get_testid_verdict_request(testid_ctx));

out:
	acvp_release_auth(testid_ctx);
	return ret;
}

static int _acvp_respond(const struct acvp_ctx *ctx,
			 const struct definition *def, const uint32_t testid)
{
	const struct acvp_opts_ctx *opts = &ctx->options;
	struct acvp_test_verdict_status *verdict;
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);

	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, testid));

	CKINT(acvp_respond_testid(testid_ctx));

	/*
	 * Skip re-downloading test session verdict if we have already obtained
	 * it or when we restarted the test vector download.
	 *
	 * Force re-download of verdict if we deleted something.
	 */
	verdict = &testid_ctx->verdict;
	if ((ret != EEXIST && ret != EINTR) ||
	    verdict->verdict != acvp_verdict_pass || opts->delete_vsid) {
		CKINT(acvp_get_testid_verdict(testid_ctx));
	}

out:
	if (atomic_read(&testid_ctx->vsids_processed) <
	    atomic_read(&testid_ctx->vsids_to_process)) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Not all test verdicts obtained for testID %u (%u missing) - use options --testid %u to retry fetching them\n",
		       testid_ctx->testid,
		       atomic_read(&testid_ctx->vsids_to_process) -
			       atomic_read(&testid_ctx->vsids_processed),
		       testid_ctx->testid);
	}

	/* Store the time the upload took */
	if (!acvp_op_get_interrupted() && !ret &&
	    atomic_read(&testid_ctx->vsids_to_process))
		acvp_record_testid_duration(testid_ctx, ACVP_DS_UPLOADDURATION);

	acvp_release_testid(testid_ctx);

	/*
	 * Clear the reported information which is irrelevant beyond this
	 * point.
	 */
	if (ret > 0)
		ret = 0;

	return ret;
}

#ifdef ACVP_USE_PTHREAD
static int acvp_process_testids_thread(void *arg)
{
	struct acvp_thread_reqresp_ctx *tdata = arg;
	const struct acvp_ctx *ctx = tdata->ctx;
	const struct definition *def = tdata->def;
	uint32_t testid = tdata->testid;
	int (*cb)(const struct acvp_ctx *ctx, const struct definition *def,
		  const uint32_t testid) = tdata->cb;

	free(tdata);

	thread_set_name(acvp_testid, testid);

	return cb(ctx, def, testid);
}
#endif

int acvp_process_testids(const struct acvp_ctx *ctx,
			 int (*cb)(const struct acvp_ctx *ctx,
				   const struct definition *def,
				   const uint32_t testid))
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	const struct acvp_opts_ctx *opts;
	const struct definition *def;
	uint32_t testids[ACVP_REQ_MAX_FAILED_TESTID];
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	datastore = &ctx->datastore;
	search = &datastore->search;
	opts = &ctx->options;

	/* Find a module definition */
	def = acvp_find_def(search, NULL);
	if (!def) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No cipher implementation found for search criteria\n");
		return -EINVAL;
	}

	/*
	 * Use thread group 0 for the register upload of one cipher definition
	 * and thread group 1 for upload of the individual vsIDs.
	 *
	 * We have one thread per test session ID. Each test session ID thread
	 * spawns one thread per vsID for uploading the test responses and
	 * downloading the verdict.
	 *
	 * The threads for the test sessions are spawned all at
	 * the beginning (to the extent possible). Thus, if we have more test
	 * sessions to be processed at the same time as threads, we will
	 * not be able to spawn any thread for uploading a vsID which will
	 * cause a deadlock. Thus, we use different thread groups for
	 * these interdependent threads to prevent that there can be a deadlock.
	 */

	/* Iterate through all modules */
	while (def) {
		unsigned int testid_count = ACVP_REQ_MAX_FAILED_TESTID;
		unsigned int i;

		/* Search for all testids for a given module */
		CKINT(ds->acvp_datastore_find_testsession(def, ctx, testids,
							  &testid_count));

		/* Iterate through all testids */
		for (i = 0; i < testid_count; i++) {
#ifdef ACVP_USE_PTHREAD
			/* Disable threading in DEBUG mode */
			if (opts->threading_disabled) {
				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "Disable threading support\n");
				CKINT(cb(ctx, def, testids[i]));
			} else {
				struct acvp_thread_reqresp_ctx *tdata;
				int ret_ancestor;

				tdata = calloc(1, sizeof(*tdata));
				CKNULL(tdata, -ENOMEM);
				tdata->ctx = ctx;
				tdata->def = def;
				tdata->testid = testids[i];
				tdata->cb = cb;
				CKINT(thread_start(acvp_process_testids_thread,
						   tdata, 0, &ret_ancestor));
				ret |= ret_ancestor;
			}
#else
			CKINT(cb(ctx, new_def, testids[i]));
#endif
		}

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

out:

#ifdef ACVP_USE_PTHREAD
	ret |= thread_wait();
#endif

	return ret;
}

int acvp_testids_refresh(const struct acvp_ctx *ctx)
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	const struct definition *def;
	struct acvp_testid_ctx *testid_ctx_head = NULL;
	uint32_t testids[ACVP_REQ_MAX_FAILED_TESTID];
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
	 * Iterate through all modules: The goal is to generate a linked
	 * list of testid_ctx instances anchored in testid_ctx_head. All
	 * members of that linked list are in need to get their JWT refreshed.
	 */
	while (def) {
		unsigned int testid_count = ACVP_REQ_MAX_FAILED_TESTID;
		unsigned int i;

		/* Search for all testids for a given module */
		CKINT(ds->acvp_datastore_find_testsession(def, ctx, testids,
							  &testid_count));

		/* Iterate through all testids */
		for (i = 0; i < testid_count; i++) {
			struct acvp_testid_ctx *testid_ctx;

			testid_ctx = calloc(1, sizeof(struct acvp_testid_ctx));
			CKNULL(testid_ctx, -ENOMEM);

			CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def,
						   testids[i]));
			CKINT(acvp_init_auth(testid_ctx));

			/* Get auth token for test session */
			CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

			ret = acvp_login_need_refresh(testid_ctx);

			/* No refresh is needed */
			if (!ret) {
				acvp_release_auth(testid_ctx);
				acvp_release_testid(testid_ctx);
			} else {
				/* Put new context to the head of the list */
				testid_ctx->next = testid_ctx_head;
				testid_ctx_head = testid_ctx;
			}
		}

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

	/*
	 * Give the linked list of testid_ctx to the login logic which
	 * refreshes them all with one ACVP server interaction. This
	 * function also ensures that the refreshed JWTs are stored permanently.
	 * Thus, this refresh operation does not need to share state information
	 * with subsequent uses of the test sessions. Hence, we can simply
	 * delete all testid_ctx instances at the end.
	 */
	CKINT(acvp_login_refresh(testid_ctx_head));

out:
	while (testid_ctx_head) {
		struct acvp_testid_ctx *testid_ctx = testid_ctx_head;

		testid_ctx_head = testid_ctx->next;

		acvp_release_auth(testid_ctx);
		acvp_release_testid(testid_ctx);
	}
	return ret;
}

DSO_PUBLIC
int acvp_respond(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_testids_refresh(ctx));

	CKINT(acvp_process_testids(ctx, &_acvp_respond));

out:
	return ret;
}

static int acvp_fetch_one_verdict_vsid(const struct acvp_vsid_ctx *vsid_ctx,
				       const struct acvp_buf *buf)
{
	const struct acvp_testid_ctx *testid_ctx;
	int ret;

	(void)buf;

	CKNULL_LOG(vsid_ctx, -EINVAL, "ACVP vsID request context missing\n");
	testid_ctx = vsid_ctx->testid_ctx;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP testID request context missing\n");

	atomic_inc((atomic_t *)&testid_ctx->vsids_to_process);
	atomic_inc(&glob_vsids_to_process);
	CKINT(acvp_get_vsid_verdict(vsid_ctx));

out:
	return ret;
}

static int acvp_fetch_verdict_vsid(struct acvp_testid_ctx *testid_ctx)
{
	ACVP_BUFFER_INIT(response);
	int ret;
	time_t expiry;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP volatile request context missing\n");

	CKINT(acvp_init_auth(testid_ctx));

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/*
	 * We try to fetch open requests, but ignore the return code as at this
	 * point, we do not actively handle meta data.
	 */
	acvp_handle_open_requests(testid_ctx);

	sig_enqueue_ctx(testid_ctx);

	/* Get verdicts for all vsIDs */
	CKINT(ds->acvp_datastore_find_responses(testid_ctx,
						acvp_fetch_one_verdict_vsid));

	/* Get verdicts for test session */
	CKINT(acvp_get_testid_verdict_request(testid_ctx));

	/* Get test ID meta data including expiry time */
	CKINT(acvp_get_testid_metadata(testid_ctx, &response));

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(testid_ctx, ACVP_DS_TESTIDMETA,
					      true, &response));

	if (!acvp_get_testsession_expiry_epoch(&response, &expiry)) {
		logger_status(LOGGER_C_ANY,
			      "Expiry date of testID %u: ", testid_ctx->testid);
		acvp_print_expiry(stderr, expiry);
		fprintf(stderr, "\n");
	}

out:
	sig_dequeue_ctx(testid_ctx);
	acvp_release_auth(testid_ctx);
	acvp_free_buf(&response);

	return ret;
}

static int _acvp_fetch_verdicts(const struct acvp_ctx *ctx,
				const struct definition *def,
				const uint32_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);

	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, testid));

	CKINT(acvp_fetch_verdict_vsid(testid_ctx));
	CKINT(acvp_get_testid_verdict(testid_ctx));

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

DSO_PUBLIC
int acvp_fetch_verdicts(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_testids_refresh(ctx));

	CKINT(acvp_process_testids(ctx, &_acvp_fetch_verdicts));

out:
	return ret;
}
