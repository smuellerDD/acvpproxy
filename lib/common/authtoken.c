/* ACVP authentication token processing
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

#include <string.h>

#include "buffer.h"
#include "build_bug_on.h"
#include "logger.h"
#include "internal.h"
#include "json_wrapper.h"
#include "definition.h"
#include "request_helper.h"
#include "totp.h"

static int _acvp_init_auth(struct acvp_auth_ctx **auth)
{
	if (*auth) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Authentication token already allocated, not allocating it again!\n");
		return -EINVAL;
	}

	*auth = calloc(1, sizeof(struct acvp_auth_ctx));
	if (!*auth)
		return -ENOMEM;

	mutex_init(&(*auth)->mutex, 0);

	return 0;
}

int acvp_init_auth_ctx(struct acvp_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	return _acvp_init_auth(&ctx->ctx_auth);
}

int acvp_init_auth(struct acvp_testid_ctx *testid_ctx)
{
	if (!testid_ctx)
		return -EINVAL;

	return _acvp_init_auth(&testid_ctx->server_auth);
}

static void _acvp_release_auth(struct acvp_auth_ctx *auth)
{
	if (!auth)
		return;

	ACVP_PTR_FREE_NULL(auth->jwt_token);
	auth->jwt_token_len = 0;
	ACVP_PTR_FREE_NULL(auth->testsession_certificate_number);
}

void acvp_release_auth_ctx(struct acvp_ctx *ctx)
{
	struct acvp_auth_ctx *auth;

	if (!ctx)
		return;

	auth = ctx->ctx_auth;
	_acvp_release_auth(auth);
	mutex_destroy(&auth->mutex);

	ACVP_PTR_FREE_NULL(ctx->ctx_auth);
}

void acvp_release_auth(struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_auth_ctx *auth;

	if (!testid_ctx || !testid_ctx->server_auth)
		return;

	auth = testid_ctx->server_auth;

	_acvp_release_auth(auth);
	mutex_destroy(&auth->mutex);

	ACVP_PTR_FREE_NULL(testid_ctx->server_auth);
}

int acvp_copy_auth(struct acvp_auth_ctx *dst, const struct acvp_auth_ctx *src)
{
	int ret = 0;

	dst->jwt_token = strndup(src->jwt_token, ACVP_JWT_TOKEN_MAX);
	CKNULL(dst->jwt_token, -ENOMEM);
	dst->jwt_token_len = src->jwt_token_len;

	dst->jwt_token_generated = src->jwt_token_generated;
	dst->testsession_certificate_id = src->testsession_certificate_id;
	dst->max_reg_msg_size = src->max_reg_msg_size;

out:
	return ret;
}

static int acvp_set_authtoken_temp(const struct acvp_testid_ctx *testid_ctx,
				   const char *authtoken)
{
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	size_t tokenlen = strlen(authtoken);
	int ret = 0;

	if (tokenlen > ACVP_JWT_TOKEN_MAX) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "New auth token too long (size %zu)\n", tokenlen);
		return -EINVAL;
	}

	_acvp_release_auth(auth);
	auth->jwt_token = strndup(authtoken, ACVP_JWT_TOKEN_MAX);
	CKNULL(auth->jwt_token, -ENOMEM);
	auth->jwt_token_len = tokenlen;

	auth->jwt_token_generated = time(NULL);

out:
	return ret;
}

int acvp_set_authtoken(const struct acvp_testid_ctx *testid_ctx,
		       const char *authtoken)
{
	const struct definition *def = testid_ctx->def;
	int ret = 0;

	CKINT(acvp_set_authtoken_temp(testid_ctx, authtoken));

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

int acvp_get_accesstoken(const struct acvp_testid_ctx *testid_ctx,
			 struct json_object *answer, bool permanently)
{
	int ret;
	const char *otp_accesstoken;

	/*
	 * Get OTP access token and store it in the JWT token location.
	 *
	 * Note, the register operation returns the real JWT which shall
	 * replace this access token.
	 *
	 * The release call here also drops the shared secret K at this point
	 * as we do not need it any more.
	 */
	CKINT(json_get_string(answer, "accessToken", &otp_accesstoken));
	/* Set the JWT token for use and write it to the data store */
	if (permanently) {
		CKINT(acvp_set_authtoken(testid_ctx, otp_accesstoken));
	} else {
		CKINT(acvp_set_authtoken_temp(testid_ctx, otp_accesstoken));
	}

out:
	return ret;
}

static bool acvp_jwt_exist(const struct acvp_auth_ctx *auth)
{
	if (!auth)
		return false;

	return (auth->jwt_token && auth->jwt_token_len);
}

static bool acvp_jwt_valid(const struct acvp_auth_ctx *auth)
{
	if (!auth)
		return false;

	return (acvp_jwt_exist(auth) &&
		(ACVP_JWT_TOKEN_LIFETIME >
		 time(NULL) - auth->jwt_token_generated));
}

int acvp_jwt_invalidate(const struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_auth_ctx *auth;
	int ret = 0;

	CKNULL(testid_ctx, -EINVAL);

	auth = testid_ctx->server_auth;
	CKNULL(auth, -EINVAL);

	auth->jwt_token_generated = 0;

out:
	return ret;
}

static int acvp_process_login(const struct acvp_testid_ctx *testid_ctx,
			      struct acvp_buf *response)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_auth_ctx *ctx_auth = ctx->ctx_auth;
	struct json_object *req = NULL, *entry = NULL;
	int ret;
	bool largeendpoint;

	/*
	 * An initial log in token is only received, if there was no previous
	 * per test session JWT authentication token, because if there would
	 * have been, this JWT would have been used during the authentication
	 * and the server would issue a re-newed token bound to the test
	 * session.
	 */
	bool initial_login = !acvp_jwt_exist(auth);

	if (!response->buf || !response->len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(response, &req, &entry));

	/* Get the size constraint information. */
	auth->max_reg_msg_size = UINT_MAX;
	ret = json_get_bool(entry, "largeEndpointRequired", &largeendpoint);
	if (!ret && largeendpoint) {
		CKINT(json_get_uint(entry, "sizeConstraint",
				    &auth->max_reg_msg_size));
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Maximum message size: %u\n",
	       auth->max_reg_msg_size);

	CKINT(acvp_get_accesstoken(testid_ctx, entry, true));

	/*
	 * It is allowed to re-use an initial login for multiple subsequent
	 * test session logins. Thus, we maintain an initial login copy
	 * in the context data structure which is re-used as long as it
	 * is valid.
	 */
	if (initial_login) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Initial login received, store it for reuse\n");
		_acvp_release_auth(ctx_auth);
		CKINT(acvp_copy_auth(ctx_auth, testid_ctx->server_auth));
	}

out:
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

static int
acvp_login_need_refresh_nonnull(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_auth_ctx *ctx_auth = ctx->ctx_auth;

	/*
	 * If we have an authentication token that has sufficient
	 * lifetime, skip the re-login.
	 */
	if (acvp_jwt_valid(auth)) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Existing test session JWT access token has sufficient lifetime\n");
		return 0;
	}

	/*
	 * If we have a valid initial login token, re-use that login token.
	 */
	if (acvp_jwt_valid(ctx_auth)) {
		int ret = acvp_copy_auth(testid_ctx->server_auth, ctx_auth);

		if (ret)
			return ret;

		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Setting context JWT access token as test session JWT access token\n");
		return 0;
	}

	return -EAGAIN;
}

int acvp_login_need_refresh(const struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;

	if (!auth) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Authentication context missing");
		return -EINVAL;
	}

	if (!acvp_login_need_refresh_nonnull(testid_ctx))
		return 0;

	/*
	 * If we have no JWT token at this point, we cannot refresh it.
	 */
	if (!acvp_jwt_exist(auth))
		return 0;

	return -EAGAIN;
}

void totp_debug_get_counter(uint64_t *counter, uint64_t *counter_stepped);
static void acvp_login_debug_print(const char *login_buf)
{
#ifdef ACVP_AUTHENTICATION_DEBUG

	uint64_t counter, counter_stepped;

	totp_debug_get_counter(&counter, &counter_stepped);

	logger(LOGGER_ERR, LOGGER_C_ANY,
	       "Failure in authentication: applied epoch: %" PRIu64
	       ", applied epoch stepped: %" PRIu64 "\n",
	       counter, counter_stepped);
	logger(LOGGER_ERR, LOGGER_C_ANY, "Login message:\n%s\n", login_buf);

#else /* ACVP_AUTHENTICATION_DEBUG */

	(void)login_buf;

#endif /* ACVP_AUTHENTICATION_DEBUG */
}

static int acvp_login_submit(struct json_object *login, const char *url,
			     struct acvp_buf *response_buf)
{
	const struct acvp_net_ctx *net;
	struct acvp_na_ex netinfo;
	ACVP_EXT_BUFFER_INIT(login_buf);
	const char *json_login;
	int ret;

	/* Convert the JSON buffer into a string */
	json_login = json_object_to_json_string_ext(
		login, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
	CKNULL_LOG(json_login, -EFAULT,
		   "JSON object conversion into string failed\n");

	login_buf.buf = (uint8_t *)json_login;
	login_buf.len = (uint32_t)strlen(json_login);

	CKINT(acvp_get_net(&net));

	/* Send the capabilities to the ACVP server. */
	netinfo.net = net;
	netinfo.url = url;
	netinfo.server_auth = NULL;
	ret = na->acvp_http_post(&netinfo, &login_buf, response_buf);

	/* Dump the password in case of an error for debugging */
	if (ret)
		acvp_login_debug_print((char *)login_buf.buf);

	if (ret < 0) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Process following server response for HTTP return code %d: %s\n",
		       -ret,
		       response_buf->buf ? (char *)response_buf->buf :
						 "<zero data>");
		goto out;
	}

	if (response_buf->buf && response_buf->len) {
		logger(LOGGER_DEBUG, LOGGER_C_ANY,
		       "Process following server response for HTTP return code 200: %s\n",
		       response_buf->buf);
	}

out:
	return ret;
}

static int acvp_login_totp(struct json_object *entry, const bool dump_register)
{
	uint32_t totp_val = 0;
	char totp_val_string[11];
	int ret = 0;

	/* Generate the OTP value based on the TOTP algorithm */
	if (!dump_register)
		CKINT(totp(&totp_val));

	/* Ensure that the snprintf format string equals TOTP size. */
	BUILD_BUG_ON(TOTP_NUMBER_DIGITS != 8);

	/* Place the password as a string */
	snprintf(totp_val_string, sizeof(totp_val_string), "%.08u", totp_val);

	json_object_object_add(entry, "password",
			       json_object_new_string(totp_val_string));

out:
	return ret;
}

/* POST /login */
int acvp_login(const struct acvp_testid_ctx *testid_ctx)
{
	const struct acvp_ctx *ctx = testid_ctx->ctx;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_auth_ctx *ctx_auth = ctx->ctx_auth;
	struct json_object *login = NULL, *entry;
	ACVP_BUFFER_INIT(response_buf);
	int ret = 0;
	char url[ACVP_NET_URL_MAXLEN];
	bool dump_register = (ctx) ? ctx->req_details.dump_register : false;

	CKNULL_LOG(auth, -EINVAL, "Authentication context missing\n");

	mutex_lock(&auth->mutex);
	mutex_lock(&ctx_auth->mutex);

	if (!acvp_login_need_refresh_nonnull(testid_ctx))
		goto out;

	login = json_object_new_array();
	CKNULL(login, -ENOMEM);

	CKINT(acvp_req_add_version(login));

	entry = json_object_new_object();
	CKNULL(entry, ENOMEM);
	CKINT(json_object_array_add(login, entry));

	CKINT(acvp_login_totp(entry, dump_register));

	/*
	 * If an auth token already exists, we perform a refresh by simply
	 * adding the associated JWT access token to the request which
	 * will cause the server to refresh the available JWT token
	 */
	if (acvp_jwt_exist(auth)) {
		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Perform a refresh of the existing JWT access token\n");
		json_object_object_add(entry, "accessToken",
				       json_object_new_string(auth->jwt_token));
	}

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				login, JSON_C_TO_STRING_PRETTY |
					       JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	logger_status(LOGGER_C_ANY, "Logging into ACVP server%s\n",
		      (auth->jwt_token && auth->jwt_token_len) ?
				    " to refresh existing auth token" :
				    "");

	CKINT(acvp_create_url(NIST_VAL_OP_LOGIN, url, sizeof(url)));
	ret = acvp_login_submit(login, url, &response_buf);

	if (response_buf.buf && response_buf.len) {
		/* Store the debug version of the result unconditionally. */
		ret |= acvp_store_login_debug(testid_ctx, &response_buf, ret);
	}

	if (ret == -403 && !response_buf.buf) {
		if (acvp_jwt_exist(auth)) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "ACVP server rejected OTP password and/or client certificate and/or existing JWT auth token\n");
		} else {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "ACVP server rejected OTP password and/or client certificate\n");
		}
	}

	if (ret)
		goto out;

	/* Process the response and set the authentication token. */
	CKINT(acvp_process_login(testid_ctx, &response_buf));

out:
	mutex_unlock(&auth->mutex);
	mutex_unlock(&ctx_auth->mutex);
	ACVP_JSON_PUT_NULL(login);
	acvp_free_buf(&response_buf);

	return ret;
}

static int
acvp_process_login_refresh(const struct acvp_testid_ctx *testid_ctx_head,
			   struct acvp_buf *response)
{
	const struct acvp_testid_ctx *testid_ctx = testid_ctx_head;
	struct json_object *req = NULL, *entry = NULL, *jauth_array, *jauth;
	char logbuf[FILENAME_MAX];
	unsigned int max_reg_msg_size = UINT_MAX;
	unsigned int i;
	int ret;
	bool largeendpoint;

	if (!response->buf || !response->len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "No response data found\n");
		return -EINVAL;
	}

	logbuf[0] = '\0';

	/*
	 * Strip the version from the received array and return the array
	 * entry containing the answer.
	 */
	CKINT(acvp_req_strip_version(response, &req, &entry));

	/* Get the size constraint information. */
	ret = json_get_bool(entry, "largeEndpointRequired", &largeendpoint);
	if (!ret && largeendpoint) {
		CKINT(json_get_uint(entry, "sizeConstraint",
				    &max_reg_msg_size));
	}

	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Maximum message size: %u\n",
	       max_reg_msg_size);

	CKINT(json_find_key(entry, "accessToken", &jauth_array,
			    json_type_array));

	for (i = 0; i < json_object_array_length(jauth_array); i++) {
		struct acvp_auth_ctx *auth;

		CKNULL_LOG(testid_ctx, -EFAULT,
			   "No testid authentication context found\n");

		auth = testid_ctx->server_auth;

		/*
		 * In case we have a NULL auth, try to use the next
		 * testid_ctx.
		 */
		while (!auth) {
			testid_ctx = testid_ctx->next;

			CKNULL_LOG(testid_ctx, -EFAULT,
				   "No testid authentication context found\n");
			auth = testid_ctx->server_auth;
		}

		jauth = json_object_array_get_idx(jauth_array, i);
		if (!json_object_is_type(jauth, json_type_string)) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "JSON data type %s does not match expected type %s\n",
			       json_type_to_name(json_object_get_type(jauth)),
			       json_type_to_name(json_type_string));
			ret = -EINVAL;
			goto out;
		}

		/* We received a largeendpoint data size */
		if (max_reg_msg_size != UINT_MAX)
			auth->max_reg_msg_size = max_reg_msg_size;

		CKINT(acvp_set_authtoken(testid_ctx,
					 json_object_get_string(jauth)));
		CKINT(acvp_extend_string(logbuf, sizeof(logbuf), "%u ",
					 testid_ctx->testid));

		testid_ctx = testid_ctx->next;
	}

	logger_status(LOGGER_C_ANY,
		      "Refresh of auth token for test sessions: %s\n", logbuf);

out:
	ACVP_JSON_PUT_NULL(req);
	return ret;
}

/* POST /login/refresh */
int acvp_login_refresh(const struct acvp_testid_ctx *testid_ctx_head)
{
	const struct acvp_ctx *ctx;
	const struct acvp_testid_ctx *testid_ctx;
	struct json_object *login = NULL, *entry, *jauth;
	struct acvp_auth_ctx *auth;
	ACVP_BUFFER_INIT(response_buf);
	unsigned int counter = 0;
	int ret = 0;
	char logbuf[FILENAME_MAX];
	char url[ACVP_NET_URL_MAXLEN];
	bool dump_register;

	CKNULL(testid_ctx_head, 0);

	ctx = testid_ctx_head->ctx;
	dump_register = (ctx) ? ctx->req_details.dump_register : false;

	login = json_object_new_array();
	CKNULL(login, -ENOMEM);

	CKINT(acvp_req_add_version(login));

	entry = json_object_new_object();
	CKNULL(entry, ENOMEM);
	CKINT(json_object_array_add(login, entry));

	CKINT(acvp_login_totp(entry, dump_register));

	jauth = json_object_new_array();
	CKNULL(jauth, ENOMEM);
	CKINT(json_object_object_add(entry, "accessToken", jauth));

	logbuf[0] = '\0';

	for (testid_ctx = testid_ctx_head; testid_ctx != NULL;
	     testid_ctx = testid_ctx->next) {
		auth = testid_ctx->server_auth;

		if (!auth)
			continue;

		mutex_lock(&auth->mutex);
		json_object_array_add(jauth,
				      json_object_new_string(auth->jwt_token));

		counter++;

		CKINT(acvp_extend_string(logbuf, sizeof(logbuf), "%u ",
					 testid_ctx->testid));
	}

	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
	       "About to refresh of auth token for test sessions: %s\n",
	       logbuf);

	/*
	 * Dump the constructed message if requested and return (i.e. no
	 * submission).
	 */
	if (dump_register) {
		fprintf(stdout, "%s\n",
			json_object_to_json_string_ext(
				login, JSON_C_TO_STRING_PRETTY |
					       JSON_C_TO_STRING_NOSLASHESCAPE));
		ret = 0;
		goto out;
	}

	logger_status(
		LOGGER_C_ANY,
		"Logging into ACVP server to refresh %u existing auth tokens",
		counter);

	CKINT(acvp_create_url(NIST_VAL_OP_LOGIN_REFRESH, url, sizeof(url)));
	json_logger(LOGGER_DEBUG, LOGGER_C_TOTP, login, "Register with");
	CKINT(acvp_login_submit(login, url, &response_buf));

	/* Process the response and set the authentication token. */
	CKINT(acvp_process_login_refresh(testid_ctx_head, &response_buf));

out:
	/* Unlock the test session auth token */
	for (testid_ctx = testid_ctx_head; testid_ctx != NULL;
	     testid_ctx = testid_ctx->next) {
		auth = testid_ctx->server_auth;
		if (!auth)
			continue;
		mutex_unlock(&auth->mutex);
	}

	ACVP_JSON_PUT_NULL(login);
	acvp_free_buf(&response_buf);

	return ret;
}
