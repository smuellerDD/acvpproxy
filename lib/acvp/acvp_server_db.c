/*
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

#include "binhexbin.h"
#include "internal.h"
#include "request_helper.h"

static int _acvp_list_server_db(const struct acvp_ctx *ctx,
				const struct definition *def)
{
	struct acvp_testid_ctx *testid_ctx = NULL;
	int ret;

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->def = def;
	testid_ctx->ctx = ctx;

	CKINT(acvp_init_auth(testid_ctx));

	CKINT(acvp_sync_metadata(testid_ctx));

out:
	acvp_release_auth(testid_ctx);
	acvp_release_testid(testid_ctx);

	return ret;
}

DSO_PUBLIC
int acvp_server_db_list(const struct acvp_ctx *ctx)
{
	const struct acvp_datastore_ctx *datastore;
	const struct acvp_search_ctx *search;
	const struct acvp_opts_ctx *opts;
	struct definition *def;
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

	if (!opts->show_db_entries)
		return 0;

	/* Find a module definition */
	def = acvp_find_def(search, NULL);
	if (!def) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No cipher implementation found for search criteria\n");
		return -EINVAL;
	}

	while (def) {
		CKINT(_acvp_list_server_db(ctx, def));

		/* Check if we find another module definition. */
		def = acvp_find_def(search, def);
	}

out:
	return ret;
}

DSO_PUBLIC
int acvp_server_db_search(struct acvp_ctx *ctx,
			  const enum acvp_server_db_search_type search_type,
			  const char *searchstr)
{
	struct acvp_opts_ctx *opts = &ctx->options;
	struct acvp_testid_ctx *testid_ctx = NULL;
	unsigned int show_type;
	int ret;
	char url[ACVP_NET_URL_MAXLEN], searchstr_html[128];

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");
	CKNULL_LOG(search_type, -EINVAL, "No search type provided\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	switch (search_type) {
	case NIST_SERVER_DB_SEARCH_VENDOR:
		CKINT(acvp_create_url(NIST_VAL_OP_VENDOR, url, sizeof(url)));
		show_type = ACVP_OPTS_SHOW_VENDOR;
		opts->show_db_entries = ACVP_OPTS_SHOW_VENDOR;
		break;
	case NIST_SERVER_DB_SEARCH_ADDRESSES:
		CKINT(acvp_create_url(NIST_VAL_OP_ADDRESSES, url, sizeof(url)));
		show_type = ACVP_OPTS_SHOW_PERSON;
		opts->show_db_entries = ACVP_OPTS_SHOW_PERSON;
		break;
	case NIST_SERVER_DB_SEARCH_PERSONS:
		CKINT(acvp_create_url(NIST_VAL_OP_PERSONS, url, sizeof(url)));
		show_type = ACVP_OPTS_SHOW_PERSON;
		opts->show_db_entries = ACVP_OPTS_SHOW_PERSON;
		break;
	case NIST_SERVER_DB_SEARCH_OE:
		CKINT(acvp_create_url(NIST_VAL_OP_OE, url, sizeof(url)));
		show_type = ACVP_OPTS_SHOW_OE;
		opts->show_db_entries = ACVP_OPTS_SHOW_OE;
		break;
	case NIST_SERVER_DB_SEARCH_MODULE:
		CKINT(acvp_create_url(NIST_VAL_OP_MODULE, url, sizeof(url)));
		show_type = ACVP_OPTS_SHOW_MODULE;
		opts->show_db_entries = ACVP_OPTS_SHOW_MODULE;
		break;
	case NIST_SERVER_DB_SEARCH_DEPENDENCY:
		CKINT(acvp_create_url(NIST_VAL_OP_DEPENDENCY, url,
				      sizeof(url)));
		show_type = ACVP_OPTS_SHOW_OE;
		opts->show_db_entries = ACVP_OPTS_SHOW_OE;
		break;
	default:
		logger(LOGGER_ERR, LOGGER_C_ANY, "Unknown search type %u\n",
		       search_type);
		ret = -EINVAL;
		goto out;
	}

	/* Set a query option consisting of vendor_name */
	CKINT(bin2hex_html_from_url(searchstr, (uint32_t)strlen(searchstr),
				    searchstr_html, sizeof(searchstr_html)));
	CKINT(acvp_append_urloptions(searchstr_html, url, sizeof(url)));

	testid_ctx = calloc(1, sizeof(*testid_ctx));
	if (!testid_ctx)
		return -ENOMEM;

	testid_ctx->ctx = ctx;

	CKINT(acvp_init_auth(testid_ctx));

	CKINT(acvp_paging_get(testid_ctx, url, show_type, NULL, NULL));

out:
	acvp_release_auth(testid_ctx);
	acvp_release_testid(testid_ctx);

	return ret;
}
