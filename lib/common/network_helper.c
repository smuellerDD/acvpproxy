/*
 * Copyright (C) 2019 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "internal.h"

static int _acvp_net_op(const struct acvp_testid_ctx *testid_ctx,
			const char *url, const struct acvp_ext_buf *submit,
			struct acvp_buf *response, enum acvp_http_type nettype)
{
	const struct acvp_net_ctx *net;
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	struct acvp_na_ex netinfo;
	int ret;

	/* Refresh the ACVP JWT token by re-logging in. */
	CKINT(acvp_login(testid_ctx));

	CKINT(acvp_get_net(&net));
	netinfo.net = net;
	netinfo.url = url;
	netinfo.server_auth = auth;

	mutex_reader_lock(&auth->mutex);
	switch (nettype) {
	case acvp_http_none:
		ret = 0;
		break;
	case acvp_http_post:
		CKNULL_LOG(submit, -EINVAL, "Submit buffer missing\n");
		CKNULL_LOG(response, -EINVAL, "Response buffer missing\n");
		ret = na->acvp_http_post(&netinfo, submit, response);
		break;
	case acvp_http_post_multi:
		CKNULL_LOG(submit, -EINVAL, "Submit buffer missing\n");
		CKNULL_LOG(response, -EINVAL, "Response buffer missing\n");
		ret = na->acvp_http_post_multi(&netinfo, submit, response);
		break;
	case acvp_http_put:
		CKNULL_LOG(submit, -EINVAL, "Submit buffer missing\n");
		CKNULL_LOG(response, -EINVAL, "Response buffer missing\n");
		ret = na->acvp_http_put(&netinfo, submit, response);
		break;
	case acvp_http_get:
		CKNULL_LOG(response, -EINVAL, "Response buffer missing\n");
		ret = na->acvp_http_get(&netinfo, response);
		break;
	case acvp_http_delete:
		ret = na->acvp_http_delete(&netinfo, response);
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY, "Wrong HTTP submit type %u\n",
		       nettype);
		ret = -EINVAL;
		break;
	}
	mutex_reader_unlock(&auth->mutex);

	if (!ret || ret < -200) {
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "HTTP return code: %d\n",
		       ret ? -ret : 200);
	}

	if (nettype != acvp_http_delete) {
		if (!response->buf || !response->len)
			goto out;

		logger(ret ? LOGGER_VERBOSE : LOGGER_DEBUG, LOGGER_C_ANY,
		       "Process following server response: %s\n",
		       response->buf);
	}

out:
	return ret;
}

int acvp_net_op(const struct acvp_testid_ctx *testid_ctx, const char *url,
		const struct acvp_ext_buf *submit, struct acvp_buf *response,
		enum acvp_http_type nettype)
{
	struct acvp_auth_ctx *auth = testid_ctx->server_auth;
	enum acvp_error_code code = ACVP_ERR_NO_ERR;
	int ret;

	CKNULL_LOG(na, -EFAULT, "No network backend registered\n");
	CKNULL_LOG(auth, -EINVAL, "Authentication context missing\n");

	ret = _acvp_net_op(testid_ctx, url, submit, response, nettype);
	CKINT(acvp_error_convert(response, ret, &code));

	/*
	 * We got an authentication error - invalidate the JWT and try
	 * to log in once again. The invalidation implies that acvp_login
	 * will definitely refresh the JWT.
	 */
	if (code == ACVP_ERR_AUTH_JWT_EXPIRED) {
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "Authentication error received - force refresh of auth token and retry network operation\n");
		CKINT(acvp_jwt_invalidate(testid_ctx));
		CKINT(_acvp_net_op(testid_ctx, url, submit, response, nettype));
		CKINT(acvp_error_convert(response, ret, &code));
	}

	if (code != ACVP_ERR_NO_ERR)
		ret = (int)code;

	if (ret && response && response->buf && response->len) {
		logger(LOGGER_ERR, LOGGER_C_ANY, "Server error response: %s\n",
		       response->buf);
	}

out:
	return ret;
}
