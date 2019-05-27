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

static size_t acvp_curl_read_cb(char *buffer, size_t size, size_t nitems,
				void *userdata)
{
	struct acvp_buf *send_buf = (struct acvp_buf *)userdata;
	size_t sendsize = (size * nitems);

	if (!send_buf)
		return 0;

	if (sendsize > send_buf->len)
		sendsize = send_buf->len;

	if (!sendsize)
		return 0;

	memcpy(buffer, send_buf->buf, sendsize);
	send_buf->buf += sendsize;
	send_buf->len -= sendsize;

	logger(LOGGER_DEBUG2, LOGGER_C_CURL, "Number of bytes uploaded: %zu\n",
	       sendsize);

	return sendsize;
}

static size_t acvp_curl_write_cb(void *ptr, size_t size, size_t nmemb,
				 void *userdata)
{
	struct acvp_buf *response_buf = (struct acvp_buf *)userdata;
	size_t bufsize = (size * nmemb);
	size_t totalsize;
	uint8_t *resp_p;

	if (!response_buf) {
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Retrieved data size : %u\n", bufsize);
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "Retrieved data: %s\n",
		       ptr);
		return bufsize;
	}

	if (!bufsize)
		return 0;

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

	if (!response_buf->buf) {
		response_buf->len = 0;
		return 0;
	}

	resp_p = response_buf->buf + response_buf->len;
	response_buf->len = totalsize;

	memcpy(resp_p, ptr, bufsize);

	/* NULL-terminate string */
	response_buf->buf[response_buf->len] = '\0';

	logger(LOGGER_DEBUG2, LOGGER_C_CURL,
	       "Current complete retrieved data (len %u): %s\n",
	       response_buf->len, response_buf->buf);

	return bufsize;
}

static int
acvp_curl_add_auth_hdr(const struct acvp_auth_ctx *auth,
			struct curl_slist **slist)
{
	size_t bearer_size;
	char *bearer;
	const char bearer_header[] = "Authorization: Bearer ";

	/* Create the Authorzation header if needed */
	if (!slist || !auth || !auth->jwt_token || !auth->jwt_token_len)
		return 0;

	bearer_size = auth->jwt_token_len + sizeof(bearer_header);
	bearer = calloc(1, bearer_size);
	if (!bearer)
		return -ENOMEM;

        snprintf(bearer, bearer_size, "%s%s", bearer_header, auth->jwt_token);
	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "HTTP Authentication header: %s\n", bearer);
        *slist = curl_slist_append(*slist, bearer);
        free(bearer);

	return 0;
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

	if (logger_get_verbosity(LOGGER_C_CURL) < LOGGER_DEBUG)
		return;

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
			fprintf(stderr, "%s\n", slist->data);
		}
	}
}

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
	ACVP_BUFFER_INIT(submit_tmp);
	const char *url = netinfo->url, *http_type_str;
	char useragent[30];
	int ret;
	unsigned int retries = 0;

	CKNULL_LOG(net, -EINVAL, "Network context missing\n");
	CKNULL_LOG(url, -EINVAL, "URL missing\n");

	CKINT(acvp_versionstring_short(useragent, sizeof(useragent)));

	if (submit_buf)
		slist = curl_slist_append(slist,
					  "Content-Type: application/json");

	CKINT(acvp_curl_add_auth_hdr(auth, &slist));

	curl = curl_easy_init();
	CKNULL(curl, -ENOMEM);
	CKINT(curl_easy_setopt(curl, CURLOPT_URL, url));
	CKINT(curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L));
	CKINT(curl_easy_setopt(curl, CURLOPT_USERAGENT, useragent));
	CKINT(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist));

	/* Required for multi-threaded applications */
	CKINT(curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L));

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
	case acvp_http_get:
		http_type_str = "GET";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP GET operation\n");
		/* Nothing special */
		break;
	case acvp_http_post:
		http_type_str = "POST";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP POST operation\n");
		if (!submit_buf || !submit_buf->buf || !submit_buf->len) {
			logger(LOGGER_WARN, LOGGER_C_CURL, "Nothing to POST\n");
			ret = -EINVAL;
			goto out;
		}
		CKINT(curl_easy_setopt(curl, CURLOPT_POST, 1L));
		CKINT(curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
				       (curl_off_t) submit_buf->len));
		CKINT(curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
				       submit_buf->buf));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "About to HTTP POST the following data:\n%s\n",
		       submit_buf->buf);
		break;
	case acvp_http_put:
		http_type_str = "PUT";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP PUT operation\n");
		if (!submit_buf || !submit_buf->buf || !submit_buf->len) {
			logger(LOGGER_WARN, LOGGER_C_CURL, "Nothing to PUT\n");
			ret = -EINVAL;
			goto out;
		}

		/*
		 * We need a temporary buffer as we need to read parts of the
		 * buffer and thus adjust the pointer and length field.
		 */
		submit_tmp.buf = submit_buf->buf;
		submit_tmp.len = submit_buf->len;
		CKINT(curl_easy_setopt(curl, CURLOPT_READFUNCTION,
				       acvp_curl_read_cb));
		CKINT(curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L));
		CKINT(curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
				       (curl_off_t)submit_buf->len));
		CKINT(curl_easy_setopt(curl, CURLOPT_READDATA,
				       &submit_tmp));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "About to HTTP PUT the following data:\n%s\n",
		       submit_buf->buf);
		break;
	case acvp_http_delete:
		http_type_str = "DELETE";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP DELETE operation\n");
		CKINT(curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE"));
		break;
	default:
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unhandled HTTP request option %u\n", http_type);
		ret = -EINVAL;
		goto out;
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
	CKINT(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			       acvp_curl_write_cb));

	/*
	 * Clear any interrupt triggered by signal handler to allow
	 * signal handler to perform network requests.
	 */
	acvp_curl_clear_interrupt();

	/* Perform the HTTP request */
	while (retries < ACVP_CURL_MAX_RETRIES) {
		cret = curl_easy_perform(curl);
		if (cret == CURLE_OK) {
			ret = 0;
			break;
		}

		ret = -ECONNREFUSED;

		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Curl HTTP operation failed with code %d (%s)\n",
		       cret,  curl_easy_strerror(cret));

		if (cret == CURLE_RECV_ERROR)
			break;

		retries++;
		if (retries < ACVP_CURL_MAX_RETRIES)
			CKINT(sleep_interruptible(10, &acvp_curl_interrupted));
	}

	if (ret)
		goto out;

	acvp_curl_log_peer_cert(curl);

	/* Get the HTTP response status code from the server */
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &ret);
	if (ret == HTTP_OK) {
		ret = 0;
	} else {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unable to HTTP %s data for URL %s: %d\n", http_type_str,
		       url, ret);
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
				     acvp_http_post);
}

static int acvp_curl_http_get(const struct acvp_na_ex *netinfo,
			      struct acvp_buf *response_buf)
{
	return acvp_curl_http_common(netinfo, NULL, response_buf,
				     acvp_http_get);
}

static int acvp_curl_http_put(const struct acvp_na_ex *netinfo,
			      const struct acvp_buf *submit_buf,
			      struct acvp_buf *response_buf)
{
	return acvp_curl_http_common(netinfo, submit_buf, response_buf,
				     acvp_http_put);
}

static int acvp_curl_http_delete(const struct acvp_na_ex *netinfo)
{
	return acvp_curl_http_common(netinfo, NULL, NULL, acvp_http_delete);
}

extern int acvp_openssl_thread_setup(void);
static int acvp_curl_library_init(void)
{
	if (curl_global_init(CURL_GLOBAL_ALL))
		return -EFAULT;

	return acvp_openssl_thread_setup();
}

static void acvp_curl_library_exit(void)
{
	curl_global_cleanup();
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
	if (acvp_curl_library_init() == 0) {
		atexit(acvp_curl_library_exit);
		acvp_register_na(&acvp_netaccess_curl);
	}
}
