/* ACVP authentication token processing
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

#include <string.h>

#include "buffer.h"
#include "build_bug_on.h"
#include "logger.h"
#include "internal.h"
#include "json_wrapper.h"
#include "definition.h"
#include "request_helper.h"
#include "totp.h"

int acvp_init_auth(struct acvp_testid_ctx *testid_ctx)
{
	if (!testid_ctx)
		return -EINVAL;

	if (testid_ctx->server_auth) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Authentication token already allocated, not allocating it again!\n");
		return -EINVAL;
	}

	testid_ctx->server_auth = calloc(1, sizeof(struct acvp_auth_ctx));
	if (!testid_ctx->server_auth)
		return -ENOMEM;

	mutex_init(&testid_ctx->server_auth->mutex, 0);

	return 0;
}

static void _acvp_release_auth(struct acvp_auth_ctx *auth)
{
	if (!auth)
		return;

	ACVP_PTR_FREE_NULL(auth->jwt_token);
	auth->jwt_token_len = 0;
}

void acvp_release_auth(struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_auth_ctx *auth;

	if (!testid_ctx)
		return;

	auth = testid_ctx->server_auth;
	_acvp_release_auth(auth);
	mutex_destroy(&auth->mutex);

	ACVP_PTR_FREE_NULL(testid_ctx->server_auth);
}

int acvp_set_authtoken(const struct acvp_testid_ctx *testid_ctx,
		       const char *authtoken)
{
	const struct definition *def = testid_ctx->def;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	int ret = 0;

	_acvp_release_auth(auth);
	auth->jwt_token = strndup(authtoken, ACVP_JWT_TOKEN_MAX);
	CKNULL(auth->jwt_token, -ENOMEM);
	auth->jwt_token_len = strlen(auth->jwt_token);

	auth->jwt_token_generated = time(NULL);

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Access token: %s\n", auth->jwt_token);

	/* Store the refreshed JWT auth token */
	if (def)
		CKINT(ds->acvp_datastore_write_authtoken(testid_ctx));

out:
	return ret;
}

int acvp_get_max_msg_size(const struct acvp_testid_ctx *testid_ctx,
			  uint32_t *size)
{
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;

	mutex_lock(&auth->mutex);
	*size = auth->max_reg_msg_size;
	mutex_unlock(&auth->mutex);

	return 0;
}

static int acvp_process_login(const struct acvp_testid_ctx *testid_ctx,
			      struct acvp_buf *response)
{
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct json_object *req = NULL, *entry = NULL;
	const char *otp_accesstoken;
	int ret;
	bool largeendpoint;

	if (!response->buf || !response->len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	logger(LOGGER_DEBUG,LOGGER_C_ANY,
	       "Process following server response: %s\n", response->buf);

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(response->buf, &req, &entry));

	/*
	 * Get OTP access token and store it in the JWT token location.
	 *
	 * Note, the register operation returns the real JWT which shall
	 * replace this access token.
	 *
	 * The release call here also drops the shared secret K at this point
	 * as we do not need it any more.
	 */
	CKINT(json_get_string(entry, "accessToken", &otp_accesstoken));

	/* Get the size constraint information. */
	auth->max_reg_msg_size = UINT_MAX;
	ret = json_get_bool(entry, "largeEndpointRequired", &largeendpoint);
	if (!ret && largeendpoint) {
		unsigned long val;
		const char *sizeconstraint;

		CKINT(json_get_string(entry, "sizeConstraintMessage",
				      &sizeconstraint));

		val = strtoul(sizeconstraint, NULL, 10);
		if (val >= UINT_MAX) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "Cannot parse message size constraint string into 32 bit integer: %s\n",
			       sizeconstraint);
			ret = -ERANGE;
			goto out;
		}

		auth->max_reg_msg_size = (uint32_t)val;
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Maximum message size: %u\n",
	       auth->max_reg_msg_size);

	/* Set the JWT token for use and write it to the data store */
	CKINT(acvp_set_authtoken(testid_ctx, otp_accesstoken));

out:
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

/* POST /login */
int acvp_login(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	const struct acvp_req_ctx *req_details = &ctx->req_details;
	const struct acvp_net_ctx *net;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_na_ex netinfo;
	struct json_object *login = NULL, *entry = NULL;
	ACVP_BUFFER_INIT(login_buf);
	ACVP_BUFFER_INIT(response_buf);
	const char *json_login;
	char url[ACVP_NET_URL_MAXLEN];
	uint32_t totp_val = 0;
	int ret = 0, ret2;
	char totp_val_string[11];

	CKNULL_LOG(auth, -EINVAL, "Authentication context missing\n");

	mutex_lock(&auth->mutex);

	/*
	 * If we have an authentication token that has sufficient lifetime,
	 * skip the re-login.
	 */
	if (auth->jwt_token && auth->jwt_token_len &&
	    (ACVP_JWT_TOKEN_LIFETIME > time(NULL) - auth->jwt_token_generated)) {
		mutex_unlock(&auth->mutex);
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Existing JWT access token has sufficient lifetime\n");
		return 0;
	}

	login = json_object_new_array();
	CKNULL(login, -ENOMEM);

	CKINT(acvp_req_add_version(login));

	/* Generate the OTP value based on the TOTP algorithm */
	if (!req_details->dump_register)
		CKINT(totp(&totp_val));

	/* Ensure that the snprintf format string equals TOTP size. */
	BUILD_BUG_ON(TOTP_NUMBER_DIGITS != 8);

	/* Place the password as a string */
	snprintf(totp_val_string, sizeof(totp_val_string), "%.08u", totp_val);

	entry = json_object_new_object();
	CKNULL(entry, ENOMEM);
	json_object_object_add(entry, "password",
			       json_object_new_string(totp_val_string));

	/*
	 * If an auth token already exists, we perform a refresh by simply
	 * adding the associated JWT access token to the request which
	 * will cause the server to refresh the available JWT token
	 */
	if (auth->jwt_token && auth->jwt_token_len) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Perform a refresh of the existing JWT access token\n");
		json_object_object_add(entry, "accessToken",
				       json_object_new_string(auth->jwt_token));
	}

	CKINT(json_object_array_add(login, entry));
	entry = NULL;

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (req_details->dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(login,
					JSON_C_TO_STRING_PRETTY |
					JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	/* Convert the JSON buffer into a string */
	json_login = json_object_to_json_string_ext(login,
					JSON_C_TO_STRING_PLAIN |
					JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_login, -EFAULT,
		   "JSON object conversion into string failed\n");

	logger_status(LOGGER_C_ANY, "Logging into ACVP server%s\n",
		      (auth->jwt_token && auth->jwt_token_len) ?
		       " to refresh existing auth token" : "" );

	login_buf.buf = (uint8_t *)json_login;
	login_buf.len = strlen(json_login);

	CKINT(acvp_get_net(&net));
	CKINT(acvp_create_url(NIST_VAL_OP_LOGIN, url, sizeof(url)));

	/* Send the capabilities to the ACVP server. */
	netinfo.net = net;
	netinfo.url = url;
	netinfo.server_auth = testid_ctx->server_auth;
	ret2 = na->acvp_http_post(&netinfo, &login_buf, &response_buf);

	if (!response_buf.buf || !response_buf.len)
		goto out;

	logger(ret2 ? LOGGER_ERR : LOGGER_DEBUG, LOGGER_C_ANY,
	       "Process following server response: %s\n", response_buf.buf);

	/* Store the debug version of the result unconditionally. */
	CKINT(acvp_store_login_debug(testid_ctx, &response_buf, ret2));

#if 0
	/* Dump the password in case of an error for debugging */
	if (ret2) {
		/* No error handling as this is a debug message only */
		time_t now = time(NULL);
		struct tm now_detail;

		localtime_r(&now, &now_detail);

		logger(LOGGER_ERR,
		       "Falure in authentication with passcode %s (time: %lu %d%.2d%.2d_%.2d-%.2d-%.2d)\n",
		       totp_val_string, now,
		       now_detail.tm_year + 1900,
		       now_detail.tm_mon + 1,
		       now_detail.tm_mday,
		       now_detail.tm_hour,
		       now_detail.tm_min,
		       now_detail.tm_sec);
	}
#endif

	if (ret2) {
		ret = ret2;
		goto out;
	}

	/* Process the response and download the vectors. */
	CKINT(acvp_process_login(testid_ctx, &response_buf));

out:
	mutex_unlock(&auth->mutex);
	ACVP_JSON_PUT_NULL(login);
	ACVP_JSON_PUT_NULL(entry);
	acvp_free_buf(&response_buf);

	return ret;
}
