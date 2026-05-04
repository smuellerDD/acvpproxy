/* Registering of RBG and submit of data
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include <dirent.h>
#include <fcntl.h>
#include <libgen.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "rbgproxy.h"
#include "binhexbin.h"
#include "rbg_internal.h"
#include "hash/sha256.h"
#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"
#include "sleep.h"
#include "term_colors.h"
#include "threading_support.h"

#include "../esvp/esvp_internal.h"

#include <json-c/json.h>

/***************************************************************************
 * Registration handling
 ***************************************************************************/

/*
 * Build one RBG-structure as defined in
 * https://github.com/usnistgov/ESV-Server/blob/FEATURE/90C/Entropy%20Source%20Validation%20Protocol.md#4-registering-a-random-bit-generator
 */
static int rbg_register_build_internal(const struct rbg_def *rbg,
				       struct json_object *request)
{
	struct json_object *rbg_object;
	unsigned int i;
	int ret;

	/* Add the rbg array object */
	rbg_object = json_object_new_array();
	CKNULL(rbg_object, -ENOMEM);
	CKINT(json_object_object_add(request, "rbg", rbg_object));

	for (i = 0; i < rbg->num_rbg_definitions; i++) {
		CKINT(json_object_array_add(rbg_object,
					    rbg->rbg_definitions[i]));
		json_object_get(rbg->rbg_definitions[i]);

		/*
		 * Sanity check
		 */
		if (i) {
			struct json_object *es;

			if (json_find_key(rbg->rbg_definitions[i],
					  "entropySources", &es,
					  json_type_object) != -ENOENT) {
				logger(LOGGER_ERR, LOGGER_C_ANY,
				       "Only the first RBG definition is allowed to specify an entropy source!\n");
				ret = -EINVAL;
				goto out;
			}
		}
	}

out:
	return ret;
}

/*
 * This function checks if 90B definition is present or not.
 * If it is present, it simply generates a standard RBG request.
 *
 * If the 90B definition is not present, it generates a full 90B request along
 * with the 90C request as defined in https://github.com/usnistgov/ESV-Server/blob/FEATURE/90C/Entropy%20Source%20Validation%20Protocol.md#5-registering-both-an-entropy-source-and-random-bit-generator
 */
static int rbg_register_build(const struct acvp_testid_ctx *testid_ctx,
			      struct json_object *request)
{
	struct rbg_def *rbg = testid_ctx->rbg_def;
	struct esvp_es_def *es_def = testid_ctx->es_def;
	struct json_object *entry, *es;
	int ret;

	/*
	 * Safety check
	 */
	if (!rbg->num_rbg_definitions)
		return -EINVAL;

	if (!es_def)
		es_def = testid_ctx->def->es;

	if (json_find_key(rbg->rbg_definitions[0], "entropySources", &es,
			  json_type_object) == -ENOENT) {

		if (es_def) {
			logger(LOGGER_VERBOSE, LOGGER_C_ANY,
			       "No entropy source definition found, trying to register entropy source along with RBG\n");
			rbg->esv_submission = true;
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "No entropy source definition found in RBG definition but also no ESV defined for the current module! The RBG-Proxy is unable to auto-resolve the entropy source definition.\n");
			ret = -EINVAL;
			goto out;
		}
	}

	/*
	 * TODO:
	 * 1. add the existing ACVP/ESV certs to the definition
	 */

	/* Array entry for version */
	CKINT(acvp_req_add_version(request));

	/* Array entry for request */
	entry = json_object_new_object();
	CKNULL(entry, -ENOMEM);
	CKINT(json_object_array_add(request, entry));

	if (rbg->esv_submission) {
		struct json_object *wrapper;

		/* Add 90B */
		wrapper = json_object_new_object();
		CKNULL(wrapper, -ENOMEM);
		CKINT(json_object_object_add(entry, "90B", wrapper));
		CKINT(esvp_register_build_internal(es_def, wrapper));

		/* Add 90C */
		wrapper = json_object_new_object();
		CKNULL(wrapper, -ENOMEM);
		CKINT(json_object_object_add(entry, "90C", wrapper));
		CKINT(rbg_register_build_internal(rbg, wrapper));
	} else {
		CKINT(rbg_register_build_internal(rbg, entry));
	}

out:
	return ret;
}

/******************************************************************************
 * General processing
 ******************************************************************************/

static int rbg_get_status(struct acvp_testid_ctx *testid_ctx)
{
	char url[ACVP_NET_URL_MAXLEN];
	ACVP_BUFFER_INIT(response_buf);
	struct json_object *resp = NULL, *data = NULL;
	unsigned int i;
	int ret;

	CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_RBG, url, sizeof(url)),
		  "Creation of request URL failed\n");
	CKINT(acvp_extend_string(url, sizeof(url), "/%"PRIu64,
				 testid_ctx->testid));

	CKINT(acvp_process_retry_testid(testid_ctx, &response_buf, url));

	/* Store the testID meta data */
	CKINT(ds->acvp_datastore_write_testid(testid_ctx, RBG_DS_TESTIDSTATUS,
					      true, &response_buf));

	/* Strip the version array entry and get the data. */
	CKINT(acvp_req_strip_version(&response_buf, &resp, &data));

	if (!json_object_is_type(data, json_type_array)) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Unexpected response from server\n");
		ret = -EINVAL;
		goto out;
	}

	for (i = 0; i < json_object_array_length(data); i++) {
		const char *str;
		struct json_object *resp_entry =
			json_object_array_get_idx(data, i);

		CKINT(json_get_string(resp_entry, "status", &str));

		if (strncasecmp(str, "passed", 6)) {
			logger(LOGGER_WARN, LOGGER_C_ANY,
			       "Server response for RBG object %u unsuccessful: %s\n",
			       i, str);
			ret = -EAGAIN;
			goto out;
		}
	}

	logger_status(LOGGER_C_ANY,
		      "%sRBG submission %"PRIu64" accepted by server%s\n",
		      TERM_COLOR_GREEN_INVERTED, testid_ctx->testid,
		      TERM_COLOR_NORMAL);

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&response_buf);
	return ret;
}

static int rbg_process_req_internal(struct acvp_testid_ctx *testid_ctx,
				    struct json_object *response)
{
	const struct rbg_def *rbg = testid_ctx->rbg_def;
	const char *jwt;
	int ret;

	/* Get access token */
	CKINT_LOG(json_get_string(response, "accessToken", &jwt),
		  "RBG server response does not contain expected JWT\n");

	/* Store access token in ctx and write it to disk */
	CKINT_LOG(acvp_set_authtoken(testid_ctx, jwt),
		  "Cannot set the new JWT token\n");

	CKINT(acvp_copy_auth(rbg->rbg_auth, testid_ctx->server_auth));

	//CKINT(rbg_write_status(testid_ctx));

	/* Store the definition search criteria */
	CKINT_LOG(acvp_export_def_search(testid_ctx),
		  "Cannot store the search criteria\n");

	/* Get the status about the submission */
	CKINT(rbg_get_status(testid_ctx));

out:
	if (ret < 0 && ret != -EINTR && ret != -ESHUTDOWN) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot process server request %d:\n", ret);
	}

	return ret;
}

static int rbg_process_req(struct acvp_testid_ctx *testid_ctx,
			   struct json_object *request,
			   struct acvp_buf *response)
{
	const struct rbg_def *rbg = testid_ctx->rbg_def;
	struct json_object *req = NULL, *entry = NULL;
	int ret;

	if (!response->buf || !response->len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT_LOG(acvp_req_strip_version(response, &req, &entry),
		  "Cannot find RBG response\n");

	if (rbg->esv_submission) {
		struct json_object *one_resp;

		if (!json_object_is_type(entry, json_type_object))
			return -EINVAL;

		/* Get the actual RBG response */
		CKINT(json_find_key(entry, "randomBitGenerator", &one_resp,
				    json_type_object));

		/* Extract testID URL and ID number */
		CKINT_LOG(acvp_get_testid(testid_ctx, request, one_resp),
			  "Cannot get testID from RBG server response\n");

		/* Store the testID meta data */
		CKINT(ds->acvp_datastore_write_testid(testid_ctx,
						      RBG_DS_TESTIDMETA,
						      true, response));

		/* Process the actual RBG response */
		CKINT(rbg_process_req_internal(testid_ctx, one_resp));

		/* Get and process the actual ESV response */
		testid_ctx->status_write = esvp_write_status;
		CKINT(json_find_key(entry, "entropyAssessments", &one_resp,
				    json_type_array));
		if (!testid_ctx->es_def)
			testid_ctx->es_def = testid_ctx->def->es;
		CKINT_LOG(acvp_init_acvp_auth_ctx(&testid_ctx->es_def->es_auth),
			  "Failure to initialize authtoken\n");
		CKINT(esvp_process_req_internal(testid_ctx,
			json_object_array_get_idx(one_resp, 0)));
		testid_ctx->status_write = rbg_write_status;

	} else {
		if (!json_object_is_type(entry, json_type_object))
			return -EINVAL;

		/* Extract testID URL and ID number */
		CKINT_LOG(acvp_get_testid(testid_ctx, request, entry),
			  "Cannot get testID from RBG server response\n");

		/* Store the testID meta data */
		CKINT(ds->acvp_datastore_write_testid(testid_ctx,
						      RBG_DS_TESTIDMETA,
						      true, response));

		/* Process the actual RBG response */
		CKINT(rbg_process_req_internal(testid_ctx, entry));
	}

	CKINT(rbg_write_status(testid_ctx));

out:
	ACVP_JSON_PUT_NULL(req);

	if (ret < 0 && ret != -EINTR && ret != -ESHUTDOWN) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cannot process server request %d:\n %s\n", ret,
		       response->buf);
	}

	return ret;
}

/* POST /rbgs or /combined */
static int rbg_register_op(struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details;
	struct rbg_def *rbg = testid_ctx->rbg_def;
	struct json_object *request = NULL;
	ACVP_EXT_BUFFER_INIT(register_buf);
	ACVP_BUFFER_INIT(response_buf);
	const char *json_request;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0, ret2;

	CKNULL(ctx, -EFAULT);
	req_details = &ctx->req_details;

	CKINT_LOG(acvp_init_auth(testid_ctx),
		  "Failure to initialize authtoken\n");
	CKINT_LOG(acvp_init_acvp_auth_ctx(&rbg->rbg_auth),
		  "Failure to initialize authtoken\n");

	request = json_object_new_array();
	CKNULL(request, -ENOMEM);

	CKINT(rbg_register_build(testid_ctx, request));

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				request,
				JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_request = json_object_to_json_string_ext(
		request,
		JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_request, -ENOMEM,
		   "JSON object conversion into string failed\n");

	register_buf.buf = (uint8_t *)json_request;
	register_buf.len = (uint32_t)strlen(json_request);

	if (rbg->esv_submission) {
		CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_COMBINED, url,
					  sizeof(url)),
			  "Creation of request URL failed\n");
	} else {
		CKINT_LOG(acvp_create_url(NIST_ESVP_VAL_OP_RBG, url,
					  sizeof(url)),
			  "Creation of request URL failed\n");
	}

	/* Send the entropy source request to the ACVP server. */
	ret2 = acvp_net_op(testid_ctx, url, &register_buf, &response_buf,
			   acvp_http_post);
	if (ret2)
		testid_ctx->sig_cancel_send_delete = false;

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_register_debug(testid_ctx, &response_buf, ret2));

	CKINT(acvp_request_error_handler(ret2));

	/* Process the response and download the vectors. */
	ret = rbg_process_req(testid_ctx, request, &response_buf);

	if (ret == -EAGAIN) {
		logger_status(LOGGER_C_ANY,
			      "Check at a later time with rbg-proxy --testid %"PRIu64" for status updates\n",
			      testid_ctx->testid);
		ret = 0;
	}

out:
	acvp_release_auth(testid_ctx);
	testid_ctx->server_auth = NULL;
	ACVP_JSON_PUT_NULL(request);
	acvp_free_buf(&response_buf);
	return ret;
}

static int rbg_continue_op(struct acvp_testid_ctx *testid_ctx)
{
	int ret;

	CKNULL_LOG(testid_ctx, -EINVAL,
		   "ACVP volatile request context missing\n");

	thread_set_name(acvp_testid, testid_ctx->testid);

	CKINT(acvp_init_auth(testid_ctx));

	testid_ctx->status_parse_rbg = rbg_read_status;
	testid_ctx->status_parse_esvp = esvp_read_status;
	testid_ctx->status_write = rbg_write_status;

	/* Get auth token for test session */
	CKINT(ds->acvp_datastore_read_authtoken(testid_ctx));

	/* Get the status about the submission */
	CKINT(rbg_get_status(testid_ctx));

out:
	return ret;
}

/******************************************************************************
 * APIs
 ******************************************************************************/

static int rbg_init_testid_ctx(struct acvp_testid_ctx *testid_ctx,
			       const struct acvp_ctx *ctx,
			       const struct definition *def,
			       const uint64_t testid)
{
	int ret;

	CKINT(acvp_init_testid_ctx(testid_ctx, ctx, def, testid));

	/*
	 * TODO this assignment (instead of a duplication) implies single
	 * threading. Either duplicate the full es_def, or make the es_def
	 * const and extract all volatile data from it.
	 */
	testid_ctx->rbg_def = def->rbg;

out:
	return ret;
}

static int rbg_process_one(const struct acvp_ctx *ctx,
			   const struct definition *def, uint64_t testid)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	(void)testid;

	/* Put the context on heap for signal handler */
	testid_ctx = calloc(1, sizeof(*testid_ctx));
	CKNULL(testid_ctx, -ENOMEM);
	CKINT(rbg_init_testid_ctx(testid_ctx, ctx, def, 0));

	CKINT(rbg_register_op(testid_ctx));

out:
	acvp_release_testid(testid_ctx);
	return ret;
}

DSO_PUBLIC
int rbg_register(const struct acvp_ctx *ctx)
{
	return acvp_register_cb(ctx, &rbg_process_one);
}

static void
acvp_process_testids_rbg_release(struct acvp_testid_ctx *testid_ctx)
{
	while (testid_ctx) {
		struct acvp_testid_ctx *curr = testid_ctx;

		testid_ctx = testid_ctx->next;

		acvp_release_auth(curr);
		acvp_release_testid(curr);
	}
}

static int _rbg_continue(void *_testid_ctx)
{
	struct acvp_testid_ctx *t_ctx, *testid_ctx = _testid_ctx;
	char str[4096];
	int ret = 0;
	bool incomplete = false;

	str[0] = '\0';

	for (t_ctx = testid_ctx; t_ctx; t_ctx = t_ctx->next) {
		int ret2 = rbg_continue_op(t_ctx);

		if (ret2 && ret2 != -EAGAIN) {
			ret = ret2;
			goto out;
		}

		if (ret2 == -EAGAIN)
			incomplete = true;
	}

	for (t_ctx = testid_ctx; t_ctx; t_ctx = t_ctx->next) {
		CKINT(acvp_extend_string(str, sizeof(str), " --testid %u",
					 t_ctx->testid));
	}

	if (incomplete) {
		logger_status(LOGGER_C_ANY,
			      "ESVP server number crunching not complete - to check the server again with all test sessions at once use%s\n",
			      str);
		goto out;
	}

out:
	acvp_process_testids_rbg_release(testid_ctx);
	return ret;
}

/*
 * The goal of this call is to collect all testid_ctx which can be certified
 * in one invocation. Thus, a linked list of testid_ctx structs is created
 * that belong together. This list is then processed with the provided callback.
 * The callback is responsible to process all entries in the linked list.
 *
 * Once a linked list is created and given to the callback, the function tries
 * to create the next linked list of yet unprocessed, but common testid_ctx's
 * until no unprocessed testid_ctx is present any more.
 */
static int
acvp_process_testids_rbg(const struct acvp_ctx *ctx,
			  int (*cb)(void *testid_ctx))
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	const struct acvp_opts_ctx *opts;
	const struct definition *def;
	struct definition *tmp_def;
	struct acvp_testid_ctx *testid_ctx = NULL;
	uint64_t testids[ACVP_REQ_MAX_FAILED_TESTID];
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
		unsigned int i, testid_count = ACVP_REQ_MAX_FAILED_TESTID;

		/* If the definition was already processed, skip it */
		if (def->processed) {
			def = acvp_find_def(search, def);

			/*
			 * If the def is NULL (i.e. we reached the end of the
			 * list) and we have a testid_ctx, fall through
			 * to process the testid_ctx. Otherwise continue
			 * which implies that also when def == NULL we
			 * continue to terminate the loop.
			 */
			if (!(!def && testid_ctx))
				continue;
		}

		if (def) {
			/* Search for all testids for a given module */
			CKINT(ds->acvp_datastore_find_testsession(def, ctx,
				testids, &testid_count));

			/* Iterate through all testids */
			for (i = 0; i < testid_count; i++) {
				struct acvp_testid_ctx *new_testid_ctx = NULL;

				/* Create new testid_ctx */
				new_testid_ctx = calloc(1,
					sizeof(*new_testid_ctx));
				CKNULL(new_testid_ctx, -ENOMEM);
				CKINT(rbg_init_testid_ctx(new_testid_ctx,
					ctx, def, testids[i]));

				/* Enqueue it into list of testid_ctx */
				if (testid_ctx) {
					struct acvp_testid_ctx *t_ctx;

					for (t_ctx = testid_ctx;
					     t_ctx;
					     t_ctx = t_ctx->next) {
						if (!t_ctx->next) {
							t_ctx->next = new_testid_ctx;
							break;
						}
					}
				} else {
					testid_ctx = new_testid_ctx;
				}
			}

			/* Unconsitfy harmless - requires single threadings */
			tmp_def = (struct definition *)def;
			/* Definition is processed - skip it next time */
			tmp_def->processed = true;

			/* Check if we find another module definition. */
			def = acvp_find_def(search, def);
			if (def)
				continue;
		}

		if (testid_ctx) {
			struct acvp_testid_ctx *tmp = testid_ctx;

			testid_ctx = NULL;

#ifdef ACVP_USE_PTHREAD
			/* Disable threading in DEBUG mode */
			if (opts->threading_disabled) {
				logger(LOGGER_DEBUG, LOGGER_C_ANY,
				       "Disable threading support\n");
				CKINT(cb(tmp));
			} else {
				int ret_ancestor;

				CKINT(thread_start(cb, tmp, 0, &ret_ancestor));
				ret |= ret_ancestor;
			}
#else
			CKINT(cb(tmp));
#endif
		}

		/*
		 * Start from scratch again if we do have a def at this point.
		 * - testid_ctx is freed in callback.
		*/
		def = acvp_find_def(search, NULL);
	}

out:

#ifdef ACVP_USE_PTHREAD
	ret |= thread_wait();
#endif

	acvp_process_testids_rbg_release(testid_ctx);
	return ret;
}

DSO_PUBLIC
int rbg_continue(const struct acvp_ctx *ctx)
{
	int ret;

	CKINT(acvp_testids_refresh(ctx, rbg_init_testid_ctx, NULL,
				   esvp_read_status, rbg_read_status,
				   rbg_write_status));

	CKINT(acvp_process_testids_rbg(ctx, &_rbg_continue));

out:
	return ret;
}
