/* ACVP proxy protocol handler for paged requests
 *
 * Copyright (C) 2019, Stephan Mueller <smueller@chronox.de>
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

static int acvp_paging_get_url_parameters(const char **url)
{
	size_t urllen;;
	int ret = -EINVAL;
	const char *url_p = *url;

	if (!*url)
		return 0;

	urllen = strlen(*url);

	while (urllen) {
		/* check for question mark */
		if (*url_p == 63) {
			ret = 0;
			break;
		}

		url_p++;
		urllen--;
	}

	*url = url_p;
	logger(LOGGER_DEBUG, LOGGER_C_ANY, "Paging: found URL parameters: %s\n",
	       url_p ? url_p : "none");

	return *url ? ret : -EINVAL;
}

int acvp_paging_get(const struct acvp_testid_ctx *testid_ctx, const char *url,
		    void *private,
		    int (*cb)(void *private, struct json_object *dataentry))
{
	ACVP_BUFFER_INIT(buf);
	struct json_object *resp = NULL, *pagingdata, *links, *dataarray;
	uint32_t totalcount = 0;
	unsigned int i;
	int ret, ret2;
	const char *next = NULL;
	char parametrized_url[FILENAME_MAX];
	bool incomplete;

	CKNULL(url, -EINVAL);
	CKNULL(testid_ctx, -EINVAL);

	strncpy(parametrized_url, url, sizeof(parametrized_url));
	CKINT(acvp_append_urloptions("limit=100", parametrized_url,
				     sizeof(parametrized_url)));

	/* Loop over paging reply as long as there is a next pointer */
	do {
		next = NULL;

		logger(LOGGER_DEBUG, LOGGER_C_ANY, "Paging: using URL %s\n",
		       parametrized_url);
		ret2 = acvp_process_retry_testid(testid_ctx, &buf,
						 parametrized_url);

		CKINT(acvp_store_file(testid_ctx, &buf, ret2,
				      parametrized_url));

		if (ret2) {
			ret = ret2;
			goto out;
		}

		CKINT(acvp_req_strip_version(buf.buf, &resp, &pagingdata));

		CKINT(json_get_bool(pagingdata, "incomplete", &incomplete));
		if (incomplete) {
			/* Get the links */
			CKINT(json_find_key(pagingdata, "links", &links,
					    json_type_object));

			/* The next keyword may contain a string or NULL */
			ret = json_get_string(links, "next", &next);
			if (!ret) {
				/*
				* Defensive programming: we only honor the HTTP
				* parameters
				*/
				CKINT(acvp_paging_get_url_parameters(&next));
				CKINT(acvp_replace_urloptions(next,
					parametrized_url,
					sizeof(parametrized_url)));
			}
		}

		if (!totalcount)
			CKINT(json_get_uint(pagingdata, "totalCount",
					    &totalcount));

		logger(LOGGER_VERBOSE, LOGGER_C_ANY,
		       "Paging: %u entries to process\n", totalcount);
		logger_status(LOGGER_C_ANY,
			      "Paging: %u entries to process\n", totalcount);

		/* Iterate over data array */
		CKINT(json_find_key(pagingdata, "data", &dataarray,
				    json_type_array));
		for (i = 0; i < json_object_array_length(dataarray); i++) {
			struct json_object *entry =
					json_object_array_get_idx(dataarray, i);

			CKINT(cb(private, entry));

			/* Callback indicated that we shall interrupt loop */
			if (ret == EINTR) {
				goto out;
			}

			totalcount--;

			/*
			 * Sanity operation to not loop indefinitely if server
			 * has an issue
			 */
			if (!totalcount)
				break;
		}

		ACVP_JSON_PUT_NULL(resp);
		acvp_free_buf(&buf);

	} while (next != NULL && totalcount);

out:
	ACVP_JSON_PUT_NULL(resp);
	acvp_free_buf(&buf);
	return ret;
}
