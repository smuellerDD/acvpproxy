/*
 * Copyright (C) 2019 - 2020, Stephan Mueller <smueller@chronox.de>
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

#include <ctype.h>

#include "internal.h"

/* remove wrong characters */
int acvp_req_check_string(char *string, size_t slen)
{
	if (!string || !slen)
		return 0;

	while (slen) {
		if (!isalnum(*string) && *string != '_' && *string != '-' &&
		    *string != '/' && *string != '.')
			*string = '_';

		string++;
		slen--;
	}

	return 0;
}

int acvp_req_check_filename(char *string, size_t slen)
{
	if (!string || !slen)
		return 0;

	if (!string || !slen)
		return 0;

	while (slen) {
		if (!isalnum(*string) && *string != '_' && *string != '-' &&
		    *string != '.')
			*string = '_';

		string++;
		slen--;
	}

	return 0;
}
