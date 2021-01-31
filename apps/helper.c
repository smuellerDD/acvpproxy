/*
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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

#include "helper.h"
#include "logger.h"
#include "ret_checkers.h"

int duplicate_string(char **dst, const char *src)
{
	if (*dst)
		free(*dst);
	if (src) {
		*dst = strdup(src);
		if (!(*dst)) {
			logger(LOGGER_ERR, LOGGER_C_ANY, "Out of memory\n");
			return -ENOMEM;
		}
	} else {
		*dst = NULL;
	}

	return 0;
}

int parse_fuzzy_flag(bool *fuzzy_search_flag, char **dst, const char *src)
{
	int ret;
	char *fuzzing_request;

	if (!src) {
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Empty string for fuzzy search provided\n");
		return -EINVAL;
	}

	fuzzing_request = strstr(src, "f:");

	/*
	 * Only honor the fuzzing request string if placed at the beginning
	 * of the string.
	 */
	if (fuzzing_request && fuzzing_request == src) {
		*fuzzy_search_flag = true;
		src += 2;
	}

	/*
	 * In case no fuzzy search flag is provided, we do NOT set the
	 * *fuzzy_search_flag to false, because the caller may have provided
	 * the -f command line option.
	 */

	CKINT(duplicate_string(dst, src));

out:
	return ret;
}
