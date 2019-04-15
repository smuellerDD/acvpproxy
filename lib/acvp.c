/* ACVP proxy protocol handler
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
#include <sys/mman.h>
#include <unistd.h>

#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "json_wrapper.h"
#include "definition.h"
#include "memset_secure.h"
#include "threading_support.h"
#include "totp.h"

/*****************************************************************************
 * Globals
 *****************************************************************************/
struct acvp_datastore_be *ds = NULL;
struct acvp_netaccess_be *na = NULL;

static struct acvp_net_ctx net_global;

static atomic_t acvp_lib_init = ATOMIC_INIT(0);

atomic_t glob_vsids_to_process = ATOMIC_INIT(0);
atomic_t glob_vsids_processed = ATOMIC_INIT(0);

/*****************************************************************************
 * Code for releasing memory
 *****************************************************************************/

static void acvp_release_net(struct acvp_net_ctx *net)
{
	if (!net)
		return;
	ACVP_PTR_FREE_NULL(net->server_name);
	ACVP_PTR_FREE_NULL(net->certs_ca_file);
	ACVP_PTR_FREE_NULL(net->certs_clnt_file);
	ACVP_PTR_FREE_NULL(net->certs_clnt_key_file);
	if (net->certs_clnt_passcode) {
		memset_secure(net->certs_clnt_passcode, 0,
			      strlen(net->certs_clnt_passcode));
	}
	ACVP_PTR_FREE_NULL(net->certs_clnt_passcode);
}

static void acvp_release_modinfo(struct acvp_modinfo_ctx *modinfo)
{
	if (!modinfo)
		return;
	ACVP_PTR_FREE_NULL(modinfo->specificver);
	ACVP_PTR_FREE_NULL(modinfo->specificver_filesafe);
}

static void acvp_release_datastore(struct acvp_datastore_ctx *datastore)
{
	if (!datastore)
		return;
	ACVP_PTR_FREE_NULL(datastore->basedir);
	ACVP_PTR_FREE_NULL(datastore->secure_basedir);
	ACVP_PTR_FREE_NULL(datastore->resultsfile);
	ACVP_PTR_FREE_NULL(datastore->vectorfile);
	ACVP_PTR_FREE_NULL(datastore->jwttokenfile);
	ACVP_PTR_FREE_NULL(datastore->messagesizeconstraint);
	ACVP_PTR_FREE_NULL(datastore->testsession_certificate_id);
	ACVP_PTR_FREE_NULL(datastore->verdictfile);
	ACVP_PTR_FREE_NULL(datastore->processedfile);
	ACVP_PTR_FREE_NULL(datastore->srcserver);
	ACVP_PTR_FREE_NULL(datastore->expectedfile);
}

static void acvp_release_search(struct acvp_search_ctx *search)
{
	if (!search)
		return;
	ACVP_PTR_FREE_NULL(search->modulename);
	ACVP_PTR_FREE_NULL(search->moduleversion);
	ACVP_PTR_FREE_NULL(search->vendorname);
	ACVP_PTR_FREE_NULL(search->execenv);
	ACVP_PTR_FREE_NULL(search->processor);

	search->nr_submit_testid = 0;
	search->nr_submit_vsid = 0;
}

/*****************************************************************************
 * Initialization and release
 *****************************************************************************/
ACVP_DEFINE_CONSTRUCTOR(acvp_constructor)
static void acvp_constructor(void)
{
	memset(&net_global, 0, sizeof(net_global));
}

ACVP_DEFINE_DESTRUCTOR(acvp_destructor)
static void acvp_destructor(void)
{
 	acvp_release_net(&net_global);
}

int acvp_get_net(const struct acvp_net_ctx **net)
{
	if (!net_global.server_name)
		return -EFAULT;

	*net = &net_global;
	return 0;
}

/*****************************************************************************
 * Helper code
 *****************************************************************************/
int acvp_duplicate(char **dst, const char *src)
{
	if (*dst) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Refusing to allocate new buffer where an old buffer is still present - prevent a memleak\n");
		return -EINVAL;
	}

	if (src) {
		*dst = strdup(src);
		if (!(*dst))
			return -ENOMEM;
	} else {
		*dst = NULL;
	}

	return 0;
}

void acvp_register_ds(struct acvp_datastore_be *datastore)
{
	if (ds) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Re-registering datastore callback!\n");
		return;
	}
	ds = datastore;
}

void acvp_register_na(struct acvp_netaccess_be *netaccess)
{
	if (na) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Re-registering network callback!\n");
		return;
	}
	na = netaccess;
}

bool acvp_library_initialized(void)
{
	if (!na || !ds)
		return false;
	return !!atomic_read(&acvp_lib_init);
}

/*
 * Determine the certificate type based on the file suffix
 *
 * @param curl_type must be 4 bytes in size or larger.
 */
static int acvp_cert_type(const char *file, char *curl_type,
			  size_t curl_type_len)
{
	size_t filelen = strlen(file);
	unsigned int suffixlen = 3;
	const char *suffix;

	/* We require suffix plus dot */
	if (filelen < (suffixlen + 1))
		return -EINVAL;

	suffix = file + filelen - suffixlen;

	if (!strncasecmp(suffix, "pem", suffixlen)) {
		snprintf(curl_type, curl_type_len, "%s", "PEM");
		return 0;
	}
	if (!strncasecmp(suffix, "cer", suffixlen)) {
		snprintf(curl_type, curl_type_len, "%s", "PEM");
		return 0;
	}
	if (!strncasecmp(suffix, "crt", suffixlen)) {
		snprintf(curl_type, curl_type_len, "%s", "DER");
		return 0;
	}
	if (!strncasecmp(suffix, "der", suffixlen)) {
		snprintf(curl_type, curl_type_len, "%s", "DER");
		return 0;
	}
	if (!strncasecmp(suffix, "p12", suffixlen)) {
		snprintf(curl_type, curl_type_len, "%s", "P12");
		return 0;
	}
	if (!strncasecmp(suffix, "pfx", suffixlen)) {
		snprintf(curl_type, curl_type_len, "%s", "P12");
		return 0;
	}

	logger(LOGGER_ERR, LOGGER_C_CURL,
	       "Cannot identify certificate type based on suffix -- use .pem (PEM file), .cer (PEM file), .crt (DER file), .der (DER file), .p12 (P12 file) or .pfx (P12 file) - found %s\n", suffix);

	return -EINVAL;
}

/*****************************************************************************
 * API calls
 *****************************************************************************/
DSO_PUBLIC
int acvp_set_net(const char *server_name, unsigned int port, const char *ca,
		 const char *client_cert, const char *client_key,
		 const char *passcode)
{
	struct acvp_net_ctx *net = &net_global;
	int ret = 0;

	CKNULL_LOG(server_name, -EINVAL, "Server name missing\n");
	CKNULL_LOG(client_cert, -EINVAL, "TLS client certificate missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	acvp_release_net(net);

	CKINT(acvp_duplicate(&net->server_name, server_name));

	net->server_port = port;

	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
	       "ACVP request server: %s:%u\n", net->server_name,
	       net->server_port);

	if (ca) {
		CKINT(acvp_duplicate(&net->certs_ca_file, ca));
	} else {
		net->certs_ca_file = NULL;
	}
	CKINT(acvp_duplicate(&net->certs_clnt_file, client_cert));
	CKINT(acvp_cert_type(net->certs_clnt_file,
			     net->certs_clnt_file_type,
			     sizeof(net->certs_clnt_file_type)));

	if (client_key) {
		CKINT(acvp_duplicate(&net->certs_clnt_key_file, client_key));
		CKINT(acvp_cert_type(net->certs_clnt_key_file,
				     net->certs_clnt_key_file_type,
				     sizeof(net->certs_clnt_key_file_type)));
	} else {
		net->certs_clnt_key_file = NULL;
	}

	if (passcode) {
		CKINT(acvp_duplicate(&net->certs_clnt_passcode, passcode));

		/* This call prevents paging out of memory. */
		ret = mlock(net->certs_clnt_passcode,
			    strlen(net->certs_clnt_passcode));
		if (ret) {
			ret = -errno;
			goto out;
		}
	} else {
		net->certs_clnt_passcode = NULL;
	}

	logger(LOGGER_VERBOSE, LOGGER_C_ANY,
	       "ACVP request TLS: CA (%s), client cert (%s), client key (%s)\n",
	       net->certs_ca_file ? net->certs_ca_file : "no peer verificaton",
	       net->certs_clnt_file,
	       net->certs_clnt_key_file ? net->certs_clnt_key_file : "none");

out:
	return ret;
}

DSO_PUBLIC
int acvp_set_module(struct acvp_ctx *ctx,
		    const struct acvp_search_ctx *caller_search,
		    const char *specific_ver)
{
	struct acvp_modinfo_ctx *modinfo;
	struct acvp_datastore_ctx *datastore;
	struct acvp_search_ctx *ctx_search;
	unsigned int i;
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");
	CKNULL_LOG(caller_search, -EINVAL, "Search context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	modinfo = &ctx->modinfo;
	datastore = &ctx->datastore;
	ctx_search = &datastore->search;

	if (specific_ver) {
		if (modinfo->specificver) {
			free(modinfo->specificver);
			modinfo->specificver = NULL;
		}
		CKINT(acvp_duplicate(&modinfo->specificver, specific_ver));
		CKINT(acvp_duplicate(&modinfo->specificver_filesafe,
				     specific_ver));
		CKINT(acvp_sanitize_string(modinfo->specificver_filesafe));
	} else {
		modinfo->specificver = NULL;
	}

	acvp_release_search(ctx_search);
	CKINT(acvp_duplicate(&ctx_search->modulename,
			     caller_search->modulename));
	CKINT(acvp_duplicate(&ctx_search->moduleversion,
			     caller_search->moduleversion));
	CKINT(acvp_duplicate(&ctx_search->vendorname,
			     caller_search->vendorname));
	CKINT(acvp_duplicate(&ctx_search->execenv, caller_search->execenv));
	CKINT(acvp_duplicate(&ctx_search->processor, caller_search->processor));

	ctx_search->fuzzy_name_search = caller_search->fuzzy_name_search;

	for (i = 0; i < caller_search->nr_submit_testid; i++)
		ctx_search->submit_testid[i] = caller_search->submit_testid[i];
	ctx_search->nr_submit_testid = caller_search->nr_submit_testid;

	for (i = 0; i < caller_search->nr_submit_vsid; i++)
		ctx_search->submit_vsid[i] = caller_search->submit_vsid[i];
	ctx_search->nr_submit_vsid = caller_search->nr_submit_vsid;

out:
	return ret;
}

DSO_PUBLIC
int acvp_req_production(struct acvp_ctx *ctx)
{
	struct acvp_req_ctx *req_details;
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	req_details = &ctx->req_details;

	/* Request certificate */
	req_details->certificateRequest = true;
	/* No debug request */
	req_details->debugRequest = false;
	/* Production environment - no intermediate value tests possible */
	req_details->production = true;
	/* Require encryption on the server side. */
	req_details->encryptAtRest = true;

out:
	return ret;
}

int acvp_versionstring_short(char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "ACVPProxy/%d.%d.%d",
			MAJVERSION, MINVERSION, PATCHLEVEL);
}


DSO_PUBLIC
int acvp_versionstring(char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "ACVPProxy/%d.%d.%d\nDatastore version %d",
			MAJVERSION, MINVERSION, PATCHLEVEL, ACVP_DS_VERSION);
}

DSO_PUBLIC
void acvp_ctx_release(struct acvp_ctx *ctx)
{
	struct acvp_datastore_ctx *datastore;
	struct acvp_search_ctx *search;
	int ret;

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return;
	}

	if (!ctx)
		return;

	ret = thread_wait();
	if (ret < 0)
		logger(LOGGER_WARN, LOGGER_C_ANY,
		       "At least one thread returned an error: %d\n", ret);

	datastore = &ctx->datastore;
	search = &datastore->search;

	acvp_release_modinfo(&ctx->modinfo);
	acvp_release_datastore(&ctx->datastore);
	acvp_release_search(search);

	free(ctx);
}

DSO_PUBLIC
int acvp_set_options(struct acvp_ctx *ctx, const struct acvp_opts_ctx *options)
{
	struct acvp_opts_ctx *ctx_opts;
	int ret = 0;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	ctx_opts = &ctx->options;

	memcpy(ctx_opts, options, sizeof(*ctx_opts));

out:
	return ret;
}

DSO_PUBLIC
int acvp_ctx_init(struct acvp_ctx **ctx,
		  const char *datastore_basedir,
		  const char *secure_basedir)
{
	struct acvp_req_ctx *req_details;
	struct acvp_datastore_ctx *datastore;
	int ret;

	CKNULL_LOG(ctx, -EINVAL, "ACVP request context missing\n");

	if (!acvp_library_initialized()) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "ACVP library was not yet initialized\n");
		return -EOPNOTSUPP;
	}

	*ctx = calloc(1, sizeof(struct acvp_ctx));
	CKNULL(*ctx, -ENOMEM);

	/* Defaults */
	req_details = &(*ctx)->req_details;
	/* No certificate requested */
	req_details->certificateRequest = false;
	/* Debug request */
	req_details->debugRequest = true;
	/* No production environment - intermediate value tests possible */
	req_details->production = false;
	/* Require encryption on the server side. */
	req_details->encryptAtRest = true;

	datastore = &(*ctx)->datastore;
	if (datastore_basedir) {
		CKINT(acvp_duplicate(&datastore->secure_basedir,
				     datastore_basedir));
	} else {
		CKINT(acvp_duplicate(&datastore->basedir, ACVP_DS_DATADIR));
	}

	/*
	 * Secure basedir is the same as the basedir unless configured
	 * otherwise.
	 */
	if (secure_basedir) {
		CKINT(acvp_duplicate(&datastore->secure_basedir,
				     secure_basedir));
	} else {
		CKINT(acvp_duplicate(&datastore->secure_basedir,
				     ACVP_DS_CREDENTIALDIR));
	}

	CKINT(acvp_duplicate(&datastore->resultsfile, ACVP_DS_TESTRESPONSE));
	CKINT(acvp_duplicate(&datastore->vectorfile, ACVP_DS_TESTREQUEST));
	CKINT(acvp_duplicate(&datastore->jwttokenfile, ACVP_DS_JWTAUTHTOKEN));
	CKINT(acvp_duplicate(&datastore->messagesizeconstraint,
			     ACVP_DS_MESSAGESIZECONSTRAINT));
	CKINT(acvp_duplicate(&datastore->testsession_certificate_id,
			     ACVP_DS_TESTSESSIONCERTIFICATEID));
	CKINT(acvp_duplicate(&datastore->verdictfile, ACVP_DS_VERDICT));
	CKINT(acvp_duplicate(&datastore->processedfile, ACVP_DS_PROCESSED));
	CKINT(acvp_duplicate(&datastore->srcserver, ACVP_DS_SRCSERVER));
	CKINT(acvp_duplicate(&datastore->expectedfile, ACVP_DS_EXPECTED));

out:
	return ret;
}

DSO_PUBLIC
void acvp_release(void)
{
	acvp_def_release_all();
	if (!acvp_library_initialized())
		return;

	if (!sig_handler_active())
		totp_release_seed();
	sig_uninstall_handler();
	thread_release(false, true);
}

DSO_PUBLIC
int acvp_init(const uint8_t *seed, uint32_t seed_len, time_t last_gen,
	      void (*last_gen_cb)(time_t now))
{
	int ret;

	CKNULL_LOG(seed, -EINVAL, "TOTP seed missing\n");
	CKNULL_LOG(seed_len, -EINVAL, "TOTP seed length is zero\n");

	if (!ds) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No datastore backend registered\n");
		return -EFAULT;
	}

	if (!na) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "No network access backend registered\n");
		return -EFAULT;
	}

	/*
	 * See acvp_register and acvp_respond for an explanation how the thread
	 * groups are used.
	 */
	if (!acvp_library_initialized())
		CKINT(thread_init(2));

	CKINT(totp_set_seed(seed, seed_len, last_gen, last_gen_cb));
	CKINT(sig_install_handler());

	acvp_op_enable();

	atomic_set(1, &acvp_lib_init);

out:
	return ret;
}
