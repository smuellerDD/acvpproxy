/*
 * Copyright (C) 2018 - 2022, Stephan Mueller <smueller@chronox.de>
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
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

#include "base64.h"

struct test_vector {
	uint8_t *bin;
	uint32_t binlen;
	char *encoded;
	uint32_t elen;
};

/* Test vectors from RFC4648 chapter 10 */
struct test_vector vectors[] = {
	{ (uint8_t *)"",	0, "", 0 },
	{ (uint8_t *)"f",	1, "Zg==", 4 },
	{ (uint8_t *)"fo",	2, "Zm8=", 4 },
	{ (uint8_t *)"foo",	3, "Zm9v", 4 },
	{ (uint8_t *)"foob",	4, "Zm9vYg==", 8 },
	{ (uint8_t *)"fooba",	5, "Zm9vYmE=", 8 },
	{ (uint8_t *)"foobar",	6, "Zm9vYmFy", 8 },
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

int main(int argc, char *argv[])
{
	uint8_t *bresult;
	char *result;
	size_t rlen;
	unsigned int i;
	int return_ret = 0;

	(void)argc;
	(void)argv;

	for (i = 0; i < ARRAY_SIZE(vectors); i++) {
		int ret = base64_encode(vectors[i].bin, vectors[i].binlen,
					&result, &rlen);

		if (ret)
			return ret;

		if (rlen != vectors[i].elen ||
		    strncmp(result, vectors[i].encoded, vectors[i].elen)) {
			printf("encoding: test %u failed (expected %s, received %s)\n",
			       i, vectors[i].encoded, result);
			return_ret++;
		}

		if (rlen)
			free(result);

		ret = base64_encode_safe(vectors[i].bin, vectors[i].binlen,
					 &result, &rlen);

		if (ret)
			return ret;

		if (rlen != vectors[i].elen ||
		    strncmp(result, vectors[i].encoded, vectors[i].elen)) {
			printf("encoding safe: test %u failed (expected %s, received %s)\n",
			       i, vectors[i].encoded, result);
			return_ret++;
		}

		if (rlen)
			free(result);

		ret = base64_decode(vectors[i].encoded, vectors[i].elen,
				    &bresult, &rlen);
		if (ret)
			return ret;

		if (rlen != vectors[i].binlen ||
		    memcmp(bresult, vectors[i].bin, vectors[i].binlen)) {
			printf("decoding: test %u failed (expected %s, received %s)\n",
			       i, vectors[i].bin, bresult);
			return_ret++;
		}

		if (rlen)
			free(bresult);

		ret = base64_decode_safe(vectors[i].encoded, vectors[i].elen,
					 &bresult, &rlen);
		if (ret)
			return ret;

		if (rlen != vectors[i].binlen ||
		    memcmp(bresult, vectors[i].bin, vectors[i].binlen)) {
			printf("decoding safe: test %u failed (expected %s, received %s)\n",
			       i, vectors[i].bin, bresult);
			return_ret++;
		}

		if (rlen)
			free(bresult);
	}

	return return_ret;
}
