/* Network access backend using libcurl
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>

#include "atomic_bool.h"
#include "logger.h"
#include "acvpproxy.h"
#include "internal.h"
#include "sleep.h"

#define HTTP_OK			200
#define ACVP_CURL_MAX_RETRIES	3

/*
 * Shall the ACVP operation be shut down?
 */
static atomic_bool_t acvp_curl_interrupted = ATOMIC_BOOL_INIT(false);

static void acvp_curl_interrupt(void)
{
	atomic_bool_set_true(&acvp_curl_interrupted);
}

static void acvp_curl_clear_interrupt(void)
{
	atomic_bool_set_false(&acvp_curl_interrupted);
}

static int acvp_curl_progress_callback(void *clientp, curl_off_t dltotal,
				       curl_off_t dlnow, curl_off_t ultotal,
				       curl_off_t ulnow)
{
	(void)clientp;
	(void)dltotal;
	(void)dlnow;
	(void)ultotal;
	(void)ulnow;

	return atomic_bool_read(&acvp_curl_interrupted);
}

static size_t acvp_curl_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct acvp_buf *response_buf = (struct acvp_buf *)userdata;
	unsigned int bufsize = (unsigned int)(size * nmemb);
	unsigned int totalsize;
	int ret;
	uint8_t *resp_p;

	if (!response_buf) {
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Retrieved data size : %u\n", bufsize);
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "Retrieved data: %s\n",
		       ptr);
		return bufsize;
	}

	totalsize = bufsize + response_buf->len;
	if (totalsize > ACVP_RESPONSE_MAXLEN || totalsize < response_buf->len) {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Received data is too big: %u\n", totalsize);
		return 0;
	}

	if (!response_buf->buf)
		response_buf->buf = malloc(bufsize + 1); /* add one for \0 */
	else
		response_buf->buf = realloc(response_buf->buf, totalsize + 1);
	CKNULL(response_buf->buf, 0);

	resp_p = response_buf->buf + response_buf->len;
	response_buf->len = totalsize;

	/* NULL-terminate string */
	response_buf->buf[response_buf->len] = '\0';

	memcpy(resp_p, ptr, bufsize);

	logger(LOGGER_DEBUG2, LOGGER_C_CURL,
	       "Current complete retrieved data (len %u): %s\n",
	       response_buf->len, response_buf->buf);

	return bufsize;

out:
	return ret;
}

static struct curl_slist
*acvp_curl_add_auth_hdr(const struct acvp_auth_ctx *auth,
			struct curl_slist *slist)
{
	size_t bearer_size;
	char *bearer;
	const char bearer_header[] = "Authorization: Bearer ";

	/* Create the Authorzation header if needed */
	if (!auth || !auth->jwt_token || !auth->jwt_token_len)
		return slist;

	bearer_size = auth->jwt_token_len + strlen(bearer_header) + 1;
        bearer = calloc(1, bearer_size);
	if (!bearer)
		return slist;

        snprintf(bearer, bearer_size, "%s%s", bearer_header, auth->jwt_token);
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "HTTP Authentication header: %s\n", bearer);
        slist = curl_slist_append(slist, bearer);
        free(bearer);

	return slist;
}

/*
 * This routine will log the TLS peer certificate chain, which
 * allows auditing the peer identity by inspecting the logs.
 */
static void acvp_curl_log_peer_cert(CURL *hnd)
{
	union {
		struct curl_slist *to_info;
		struct curl_certinfo *to_certinfo;
	} ptr;
	int i, ret;

	ptr.to_info = NULL;

	ret = curl_easy_getinfo(hnd, CURLINFO_CERTINFO, &ptr.to_info);
	if (ret || !ptr.to_info)
		return;

	logger(LOGGER_DEBUG, LOGGER_C_CURL,
		"TLS peer presented the following %d certificates...\n",
		ptr.to_certinfo->num_of_certs);

	for (i = 0; i < ptr.to_certinfo->num_of_certs; i++) {
		struct curl_slist *slist;
		for (slist = ptr.to_certinfo->certinfo[i];
			slist;
			slist = slist->next) {
			logger(LOGGER_DEBUG, LOGGER_C_CURL,
			       "TLS certificate %s\n", slist->data);
		}
	}
}

enum acvp_http_type {
	ACVP_HTTP_GET,
	ACVP_HTTP_POST,
	ACVP_HTTP_PUT,
	ACVP_HTTP_DELETE,
};

static int acvp_curl_http_common(const struct acvp_na_ex *netinfo,
				 const struct acvp_buf *submit_buf,
				 struct acvp_buf *response_buf,
				 enum acvp_http_type http_type)
{
	const struct acvp_net_ctx *net = netinfo->net;
	const struct acvp_auth_ctx *auth = netinfo->server_auth;
	struct curl_slist *slist = NULL;
	CURL *curl = NULL;
	CURLcode cret;
	const char *url = netinfo->url;
	char useragent[30];
	int ret;
	unsigned int retries = 0;

	CKNULL_LOG(net, -EINVAL, "Network context missing\n");
	CKNULL_LOG(url, -EINVAL, "URL missing\n");

	CKINT(acvp_versionstring(useragent, sizeof(useragent)));

	if (submit_buf)
		slist = curl_slist_append(slist,
					  "Content-Type: application/json");

	slist = acvp_curl_add_auth_hdr(auth, slist);
	CKNULL(slist, -ENOMEM);

	curl = curl_easy_init();
	CKNULL(curl, -ENOMEM);
	CKINT(curl_easy_setopt(curl, CURLOPT_URL, url));
	CKINT(curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L));
	CKINT(curl_easy_setopt(curl, CURLOPT_USERAGENT, useragent));
	CKINT(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist));

#if LIBCURL_VERSION_NUM < 0x072000
	CKINT(curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION,
			       acvp_curl_progress_callback));
	CKINT(curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, NULL));
#else
	CKINT(curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,
			       acvp_curl_progress_callback));
	CKINT(curl_easy_setopt(curl, CURLOPT_XFERINFODATA, NULL));
#endif
	CKINT(curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L));

	switch (http_type) {
	case ACVP_HTTP_GET:
		/* Nothing special */
		break;
	case ACVP_HTTP_POST:
		CKINT(curl_easy_setopt(curl, CURLOPT_POST, 1L));
		break;
	case ACVP_HTTP_PUT:
		//TODO see https://curl.haxx.se/libcurl/c/CURLOPT_UPLOAD.html whether to add read callback?!
		CKINT(curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L));
		break;
	case ACVP_HTTP_DELETE:
		CKINT(curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unhandled HTTP request option %u\n", http_type);
		ret = -EINVAL;
		goto out;
	}

	if (submit_buf && submit_buf->buf && submit_buf->len) {
		CKINT(curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
				       (curl_off_t) submit_buf->len));
		CKINT(curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
				       submit_buf->buf));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "About to HTTP POST the following data:\n%s\n",
		       submit_buf->buf);
	}

	if (logger_get_verbosity(LOGGER_C_CURL) >= LOGGER_VERBOSE)
		CKINT(curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L));

	if (net->certs_ca_file) {
		CKINT(curl_easy_setopt(curl, CURLOPT_CAINFO,
				       net->certs_ca_file));
		CKINT(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L));
		CKINT(curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L));
		logger(LOGGER_VERBOSE, LOGGER_C_CURL,
		       "TLS peer verification enabled with CA file %s.\n",
		       net->certs_ca_file);
	} else {
		CKINT(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L));
		logger(LOGGER_VERBOSE, LOGGER_C_CURL,
		       "TLS peer verification disabled.\n");
	}

	CKINT(curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L));

	if (net->certs_clnt_file) {
		CKINT(curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,
				       net->certs_clnt_file_type));
		CKINT(curl_easy_setopt(curl, CURLOPT_SSLCERT,
				       net->certs_clnt_file));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Setting certificate with type %s\n",
		       net->certs_clnt_file_type);
	}
	if (net->certs_clnt_key_file) {
		CKINT(curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,
				       net->certs_clnt_key_file_type))	;
		CKINT(curl_easy_setopt(curl, CURLOPT_SSLKEY,
				       net->certs_clnt_key_file));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Setting private key with type %s\n",
		       net->certs_clnt_key_file_type);
	}
	if (net->certs_clnt_passcode) {
		CKINT(curl_easy_setopt(curl, CURLOPT_KEYPASSWD,
				       net->certs_clnt_passcode));
	}

	/*
	 * If the caller wants the HTTP data from the server
	 * set the callback function
	 */
	CKINT(curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buf));
	CKINT(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, acvp_curl_cb));

	/*
	 * Clear any interrupt triggered by signal handler to allow
	 * signal handler to perform network requests.
	 */
	acvp_curl_clear_interrupt();

	/* Perform the HTTP request */
	while (retries < ACVP_CURL_MAX_RETRIES) {
		cret = curl_easy_perform(curl);
		if (cret == CURLE_OK)
			break;

		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Curl HTTP operation failed with code %d (%s)\n",
		       cret,  curl_easy_strerror(cret));

		retries++;
		if (retries < ACVP_CURL_MAX_RETRIES)
			CKINT(sleep_interruptible(10, &acvp_curl_interrupted));
	}

	acvp_curl_log_peer_cert(curl);

	/* Get the HTTP response status code from the server */
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &ret);
	if (ret == HTTP_OK) {
		ret = 0;
	} else {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unable to HTTP GET data for URL %s: %d\n", url,
		       ret);
		ret = -ECONNREFUSED;
	}

out:
	if (curl)
		curl_easy_cleanup(curl);
	if (slist)
		curl_slist_free_all(slist);
	return ret;
}

static int acvp_curl_http_post(const struct acvp_na_ex *netinfo,
			       const struct acvp_buf *submit_buf,
			       struct acvp_buf *response_buf)
{
	return acvp_curl_http_common(netinfo, submit_buf, response_buf,
				     ACVP_HTTP_POST);
}

static int acvp_curl_http_get(const struct acvp_na_ex *netinfo,
			      struct acvp_buf *response_buf)
{
	return acvp_curl_http_common(netinfo, NULL, response_buf,
				     ACVP_HTTP_GET);
}

static int acvp_curl_http_put(const struct acvp_na_ex *netinfo,
			      const struct acvp_buf *submit_buf,
			      struct acvp_buf *response_buf)
{
	return acvp_curl_http_common(netinfo, submit_buf, response_buf,
				     ACVP_HTTP_PUT);
}

static int acvp_curl_http_delete(const struct acvp_na_ex *netinfo)
{
	return acvp_curl_http_common(netinfo, NULL, NULL, ACVP_HTTP_DELETE);
}

static struct acvp_netaccess_be acvp_netaccess_curl = {
	&acvp_curl_http_post,
	&acvp_curl_http_get,
	&acvp_curl_http_put,
	&acvp_curl_http_delete,
	&acvp_curl_interrupt
};

ACVP_DEFINE_CONSTRUCTOR(acvp_curl_init)
static void acvp_curl_init(void)
{
	acvp_register_na(&acvp_netaccess_curl);
}
