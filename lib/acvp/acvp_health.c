/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "internal.h"
#include "json_wrapper.h"
#include "logger.h"
#include "request_helper.h"
#include "term_colors.h"

/*
 * GET https://demo.acvts.nist.gov/health
 *
 * Note, this is not the actual protocol URL!!!
 */
DSO_PUBLIC
int acvp_health(const struct acvp_ctx *ctx)
{
	const struct acvp_net_ctx *net;
	struct json_object *req = NULL, *entry, *array, *details;
	struct acvp_testid_ctx testid_ctx;
	ACVP_BUFFER_INIT(response);
	char url[ACVP_NET_URL_MAXLEN];
	const char *str, *str2;
	size_t i;
	int ret;

	memset(&testid_ctx, 0, sizeof(testid_ctx));

	/*
	 * We cannot use
	 * CKINT(acvp_create_url(NIST_VAL_OP_HEALTH, url, sizeof(url)));
	 */
	CKINT(acvp_get_net(&net));
	snprintf(url, sizeof(url), "https://%s:%u%s", net->server_name,
		 net->server_port, NIST_VAL_OP_HEALTH);
	logger(LOGGER_VERBOSE, LOGGER_C_ANY, "ACVP URL: %s\n", url);

	testid_ctx.ctx = ctx;
	CKINT(acvp_init_auth(&testid_ctx));

	CKINT(acvp_net_op(&testid_ctx, url, NULL, &response, acvp_http_get));

	CKINT(acvp_req_strip_version(&response, &req, &entry));

	CKINT(json_find_key(entry, "details", &array, json_type_array));

	for (i = 0; i < json_object_array_length(array); i++) {
		details = json_object_array_get_idx(array, i);
		CKNULL(details, -EFAULT);

		CKINT(json_get_string(details, "key", &str));
		CKINT(json_get_string(details, "status", &str2));

		fprintf(stdout, "Server status: ");

		if (!strncmp(str2, "Healthy", 7))
			fprintf_green(stdout, "%s %s", str, str2);
		else if (!strncmp(str2, "Degraded", 8))
			fprintf_yellow(stdout, "%s", str, str2);
		else
			fprintf_red(stdout, "%s", str, str2);

		CKINT(json_get_string(details, "description", &str));
		fprintf(stdout, " - %s\n", str);
	}

out:
	acvp_release_auth(&testid_ctx);
	ACVP_JSON_PUT_NULL(req);
	acvp_free_buf(&response);
	return ret;
}
