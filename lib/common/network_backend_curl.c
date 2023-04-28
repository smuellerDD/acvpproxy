/* Network access backend using libcurl
 *
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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

#define HTTP_OK 200
#define ACVP_CURL_MAX_RETRIES 3

#define CURL_CKINT(x)                                                          \
	{                                                                      \
		cret = x;                                                      \
		if (cret) {                                                    \
			ret = -EFAULT;                                         \
			goto out;                                              \
		}                                                              \
	}

/*
 * Shall the ACVP operation be shut down?
 */
static atomic_bool_t acvp_curl_interrupted = ATOMIC_BOOL_INIT(false);

static void acvp_curl_interrupt(void)
{
	atomic_bool_set_true(&acvp_curl_interrupted);
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
	send_buf->len -= (uint32_t)sendsize;

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
		       "Retrieved data size : %zu\n", bufsize);
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "Retrieved data: %s\n",
		       (char *)ptr);
		return bufsize;
	}

	if (!bufsize)
		return 0;

	totalsize = bufsize + response_buf->len;
	if (totalsize > ACVP_RESPONSE_MAXLEN || totalsize < response_buf->len) {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Received data is too big: %zu\n", totalsize);
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
	response_buf->len = (uint32_t)totalsize;

	memcpy(resp_p, ptr, bufsize);

	/* NULL-terminate string */
	response_buf->buf[response_buf->len] = '\0';

	logger(LOGGER_DEBUG2, LOGGER_C_CURL,
	       "Current complete retrieved data (len %u): %s\n",
	       response_buf->len, response_buf->buf);

	return bufsize;
}

static int acvp_curl_add_auth_hdr(const struct acvp_auth_ctx *auth,
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
	logger(LOGGER_DEBUG, LOGGER_C_CURL, "HTTP Authentication header: %s\n",
	       bearer);
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
	struct curl_certinfo *to_certinfo = NULL;
	int i;
	CURLcode ret;

	if (logger_get_verbosity(LOGGER_C_CURL) < LOGGER_DEBUG2)
		return;

	ret = curl_easy_getinfo(hnd, CURLINFO_CERTINFO, &to_certinfo);
	if (ret || !to_certinfo)
		return;

	logger(LOGGER_DEBUG, LOGGER_C_CURL,
	       "TLS peer presented the following %d certificates...\n",
	       to_certinfo->num_of_certs);

	for (i = 0; i < to_certinfo->num_of_certs; i++) {
		struct curl_slist *slist;
		for (slist = to_certinfo->certinfo[i]; slist;
		     slist = slist->next) {
			logger(LOGGER_DEBUG2, LOGGER_C_CURL, "%s\n",
			       slist->data);
		}
	}
}

static void acvp_curl_dump(const char *text, FILE *stream, unsigned char *ptr,
			   size_t size)
{
	size_t i;
	size_t c;
	unsigned int width = 0x10;

	fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n", text, (long)size,
		(long)size);

	for (i = 0; i < size; i += width) {
		fprintf(stream, "%4.4lx: ", (long)i);

		/* show hex to the left */
		for (c = 0; c < width; c++) {
			if (i + c < size)
				fprintf(stream, "%02x ", ptr[i + c]);
			else
				fputs("   ", stream);
		}

		/* show data on the right */
		for (c = 0; (c < width) && (i + c < size); c++) {
			unsigned char x =
				(ptr[i + c] >= 0x20 && ptr[i + c] < 0x80) ?
					      ptr[i + c] :
					      '.';

			fputc(x, stream);
		}

		fputc('\n', stream); /* newline */
	}
}

static int acvp_curl_debug_cb(CURL *handle, curl_infotype type, char *data,
			      size_t size, void *userptr)
{
	const char *text;
	(void)handle; /* prevent compiler warning */
	(void)userptr;

	switch (type) {
	case CURLINFO_TEXT:
		fprintf(stderr, "== Info: %s", data);
		/* FALLTHROUGH */
	case CURLINFO_END:
	default: /* in case a new one is introduced to shock us */
		return 0;

	case CURLINFO_HEADER_OUT:
		text = "=> Send header";
		break;
	case CURLINFO_DATA_OUT:
		text = "=> Send data";
		break;
	case CURLINFO_SSL_DATA_OUT:
		text = "=> Send SSL data";
		break;
	case CURLINFO_HEADER_IN:
		text = "<= Recv header";
		break;
	case CURLINFO_DATA_IN:
		text = "<= Recv data";
		break;
	case CURLINFO_SSL_DATA_IN:
		text = "<= Recv SSL data";
		break;
	}

	acvp_curl_dump(text, stderr, (unsigned char *)data, size);
	return 0;
}

static int acvp_curl_common_init(const struct acvp_na_ex *netinfo,
				 struct acvp_buf *response_buf,
				 struct curl_slist **slist, CURL **curl_ret)
{
	const struct acvp_net_ctx *net = netinfo->net;
	const struct acvp_auth_ctx *auth = netinfo->server_auth;
	CURL *curl = NULL;
	CURLcode cret;
	const char *url = netinfo->url;
	char useragent[30];
	int ret;

	CKNULL_LOG(net, -EINVAL, "Network context missing\n");
	CKNULL_LOG(url, -EINVAL, "URL missing\n");

	CKINT(acvp_versionstring_short(useragent, sizeof(useragent)));

	CKINT(acvp_curl_add_auth_hdr(auth, slist));

	curl = curl_easy_init();
	CKNULL(curl, -ENOMEM);
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_URL, url));
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L));
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_USERAGENT, useragent));
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
				    CURL_HTTP_VERSION_1_1));
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_HTTPHEADER, *slist));

	/* Required for multi-threaded applications */
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L));

#if LIBCURL_VERSION_NUM < 0x072000
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION,
				    acvp_curl_progress_callback));
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, NULL));
#else
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION,
				    acvp_curl_progress_callback));
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_XFERINFODATA, NULL));
#endif
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L));

	if (logger_get_verbosity(LOGGER_C_CURL) >= LOGGER_VERBOSE) {
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_STDERR,
					    logger_log_stream()));
	}
	if (logger_get_verbosity(LOGGER_C_CURL) >= LOGGER_DEBUG2) {
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION,
					    acvp_curl_debug_cb));
	}

	if (net->certs_ca_file) {
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_CAINFO,
					    net->certs_ca_file));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_CERTINFO, 1L));
		logger(LOGGER_VERBOSE, LOGGER_C_CURL,
		       "TLS peer verification enabled with CA file %s.\n",
		       net->certs_ca_file);
	} else {
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L));
		logger(LOGGER_VERBOSE, LOGGER_C_CURL,
		       "TLS peer verification disabled.\n");
	}

	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L));

	if (net->certs_clnt_file) {
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,
					    net->certs_clnt_file_type));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_SSLCERT,
					    net->certs_clnt_file));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Setting certificate with type %s\n",
		       net->certs_clnt_file_type);
	}
	if (net->certs_clnt_key_file) {
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE,
					    net->certs_clnt_key_file_type));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_SSLKEY,
					    net->certs_clnt_key_file));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Setting private key with type %s\n",
		       net->certs_clnt_key_file_type);
	}
	if (net->certs_clnt_passcode) {
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_KEYPASSWD,
					    net->certs_clnt_passcode));
	}

	/*
	 * If the caller wants the HTTP data from the server
	 * set the callback function
	 */
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buf));
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
				    acvp_curl_write_cb));

	*curl_ret = curl;

out:
	if (ret && curl)
		curl_easy_cleanup(curl);
	return ret;
}

static int acvp_curl_http_common(const struct acvp_na_ex *netinfo,
				 const struct acvp_ext_buf *submit_buf,
				 struct acvp_buf *response_buf,
				 enum acvp_http_type http_type)
{
	struct curl_slist *slist = NULL;
	CURL *curl = NULL;
	CURLcode cret;
	ACVP_BUFFER_INIT(submit_tmp);
	const char *url = netinfo->url, *http_type_str;
	int ret;
	unsigned int retries = 0;
	long http_response_code = 0;

	if (submit_buf)
		slist = curl_slist_append(slist,
					  "Content-Type: application/json");

	CKINT(acvp_curl_common_init(netinfo, response_buf, &slist, &curl));

	switch (http_type) {
	case acvp_http_get:
		http_type_str = "GET";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP GET operation\n");
		/* Nothing special */
		break;
	case acvp_http_post:
		http_type_str = "POST";
		if (!submit_buf || !submit_buf->buf || !submit_buf->len) {
			logger(LOGGER_WARN, LOGGER_C_CURL, "Nothing to POST\n");
			ret = -EINVAL;
			goto out;
		}
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP POST operation of following data:\n%s\n",
		       submit_buf->buf);
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_POST, 1L));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
					    (curl_off_t)submit_buf->len));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
					    submit_buf->buf));
		break;
	case acvp_http_put:
		http_type_str = "PUT";
		if (!submit_buf || !submit_buf->buf || !submit_buf->len) {
			logger(LOGGER_WARN, LOGGER_C_CURL, "Nothing to PUT\n");
			ret = -EINVAL;
			goto out;
		}
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP PUT operation of following data:\n%s\n",
		       submit_buf->buf);

		/*
		 * We need a temporary buffer as we need to read parts of the
		 * buffer and thus adjust the pointer and length field.
		 */
		submit_tmp.buf = submit_buf->buf;
		submit_tmp.len = submit_buf->len;
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_READFUNCTION,
					    acvp_curl_read_cb));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L));
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
					    (curl_off_t)submit_buf->len));
		CURL_CKINT(
			curl_easy_setopt(curl, CURLOPT_READDATA, &submit_tmp));
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "About to HTTP PUT the following data:\n%s\n",
		       submit_buf->buf);
		break;
	case acvp_http_delete:
		http_type_str = "DELETE";
		logger(LOGGER_DEBUG, LOGGER_C_CURL,
		       "Performing an HTTP DELETE operation\n");
		CURL_CKINT(curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,
					    "DELETE"));
		break;
	case acvp_http_none:
	case acvp_http_post_multi:
	default:
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unhandled HTTP request option %u\n", http_type);
		ret = -EINVAL;
		goto out;
	}

#if 0
	/* Set a specific cipher */
	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST,
				    "ECDHE-RSA-AES128-SHA256"));
#endif

	/* Perform the HTTP request */
	while (retries < ACVP_CURL_MAX_RETRIES) {
		cret = curl_easy_perform(curl);
		if (cret == CURLE_OK)
			break;

		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Curl HTTP operation failed with code %d (%s)\n", cret,
		       curl_easy_strerror(cret));

		if (cret == CURLE_RECV_ERROR) {
			ret = -ECONNREFUSED;
			goto out;
		}

		retries++;
		if (retries < ACVP_CURL_MAX_RETRIES) {
			int ret2;

			/*
			 * Do not reuse the variable ret as it must be left
			 * untouched in case it contains the error from the
			 * HTTP operation.
			 */
			ret2 = sleep_interruptible(10, &acvp_curl_interrupted);
			if (ret2 < 0) {
				ret = ret2;
				goto out;
			}
		}
	}

	acvp_curl_log_peer_cert(curl);

	/* Get the HTTP response status code from the server */
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response_code);
	if (http_response_code == HTTP_OK) {
		ret = 0;
	} else {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Unable to HTTP %s data for URL %s: %ld\n",
		       http_type_str, url, http_response_code);
		ret = -(int)http_response_code;
	}

out:
	if (curl)
		curl_easy_cleanup(curl);
	if (slist)
		curl_slist_free_all(slist);
	return atomic_bool_read(&acvp_curl_interrupted) ? -EINTR : ret;
}

static int acvp_curl_http_post(const struct acvp_na_ex *netinfo,
			       const struct acvp_ext_buf *submit_buf,
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
			      const struct acvp_ext_buf *submit_buf,
			      struct acvp_buf *response_buf)
{
	return acvp_curl_http_common(netinfo, submit_buf, response_buf,
				     acvp_http_put);
}

static int acvp_curl_http_delete(const struct acvp_na_ex *netinfo,
				 struct acvp_buf *response_buf)
{
	return acvp_curl_http_common(netinfo, NULL, response_buf,
				     acvp_http_delete);
}

static int acvp_curl_http_post_multi(const struct acvp_na_ex *netinfo,
				     const struct acvp_ext_buf *submit_buf,
				     struct acvp_buf *response_buf)
{
	const struct acvp_ext_buf *s_buf;
	struct curl_slist *slist = NULL;
	CURL *curl = NULL;
	CURLM *multi_handle = NULL;
	CURLMcode mc;
	CURLcode cret;
	curl_mime *form = NULL;
	curl_mimepart *field = NULL;
	int ret = 0, still_running = 0;

	CKINT(acvp_curl_common_init(netinfo, response_buf, &slist, &curl));

	multi_handle = curl_multi_init();
	CKNULL(multi_handle, -ENOMEM);

	form = curl_mime_init(curl);
	CKNULL(form, -ENOMEM);

	for (s_buf = submit_buf; s_buf; s_buf = s_buf->next) {
		field = curl_mime_addpart(form);
		CKNULL(field, -ENOMEM);
		CURL_CKINT(curl_mime_name(field, s_buf->data_type));
		logger(LOGGER_DEBUG, LOGGER_C_CURL, "Set mime type %s\n",
		       s_buf->data_type);
		if (s_buf->buf) {
			CURL_CKINT(curl_mime_data(
				field, (const char *)s_buf->buf, s_buf->len));
			logger(LOGGER_DEBUG, LOGGER_C_CURL,
			       "Add mime data of length %u\n", s_buf->len);
		}
		if (s_buf->filename) {
			CURL_CKINT(curl_mime_filename(field, s_buf->filename));
			logger(LOGGER_DEBUG, LOGGER_C_CURL,
			       "Add file name %s\n", s_buf->filename);
		}
	}

	CURL_CKINT(curl_easy_setopt(curl, CURLOPT_MIMEPOST, form));

	mc = curl_multi_add_handle(multi_handle, curl);
	if (mc != CURLM_OK) {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Addition of CURL easy-handle failed with code %d (%s)\n",
		       mc, curl_multi_strerror(mc));
	}

	mc = curl_multi_perform(multi_handle, &still_running);
	if (mc != CURLM_OK) {
		logger(LOGGER_WARN, LOGGER_C_CURL,
		       "Curl multi-HTTP operation failed with code %d (%s)\n",
		       mc, curl_multi_strerror(mc));
	}

	while (still_running) {
		struct timeval timeout;

		fd_set fdread;
		fd_set fdwrite;
		fd_set fdexcep;
		int maxfd = -1;

		long curl_timeo;

		curl_multi_timeout(multi_handle, &curl_timeo);
		if (curl_timeo < 0)
			curl_timeo = 1000;

		timeout.tv_sec = curl_timeo / 1000;
		timeout.tv_usec = (curl_timeo % 1000) * 1000;

		logger(LOGGER_DEBUG2, LOGGER_C_CURL,
		       "Setting the multi-form post timeout to %lu seconds, %lu microseconds\n",
		       timeout.tv_sec, timeout.tv_usec);

		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdexcep);

		/* get file descriptors from the transfers */
		mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep,
				      &maxfd);
		if (mc != CURLM_OK) {
			logger(LOGGER_ERR, LOGGER_C_ANY,
			       "curl_multi_fdset() failed, code %d.\n", mc);
			break;
		}

		if (maxfd == -1) {
			struct timeval wait = { 0, 100 * 1000 }; /* 100ms */

			logger(LOGGER_DEBUG2, LOGGER_C_CURL,
			       "Sleeping a bit\n");
			ret = select(0, NULL, NULL, NULL, &wait);
		} else {
			ret = select(maxfd + 1, &fdread, &fdwrite, &fdexcep,
				     &timeout);
		}

		switch (ret) {
		case -1:
			/* select error */
			ret = -errno;
			break;
		case 0:
		default:
			ret = 0;
			/* timeout or readable/writable sockets */
			mc = curl_multi_perform(multi_handle, &still_running);
			if (mc != CURLM_OK) {
				logger(LOGGER_WARN, LOGGER_C_CURL,
				       "Curl multi-HTTP operation failed with code %d (%s)\n",
				       mc, curl_multi_strerror(mc));
			}
			break;
		}
	}

out:
	if (multi_handle)
		curl_multi_cleanup(multi_handle);
	if (curl)
		curl_easy_cleanup(curl);
	if (form)
		curl_mime_free(form);
	if (slist)
		curl_slist_free_all(slist);
	return ret;
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
	&acvp_curl_http_post, &acvp_curl_http_post_multi, &acvp_curl_http_get,
	&acvp_curl_http_put,  &acvp_curl_http_delete,	  &acvp_curl_interrupt
};

ACVP_DEFINE_CONSTRUCTOR(acvp_curl_init)
static void acvp_curl_init(void)
{
	if (acvp_curl_library_init() == 0) {
		atexit(acvp_curl_library_exit);
		acvp_register_na(&acvp_netaccess_curl);
	}
}
