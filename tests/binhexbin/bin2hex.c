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

#include <stdlib.h>
#include <string.h>

#include "binhexbin.h"

int main(int argc, char *argv[])
{
	/* number of bytes to be converted */
#define bytesize 12
	/* input string */
	uint8_t *bin = (uint8_t *)"\xaa\x00\xbb\x11\xcc\x22\xdd\x33\xee\x44\xff\x55";
	uint8_t *bin_new;
	char *hex_l = "aa00bb11cc22dd33ee44ff55";
	char *hex_u = "AA00BB11CC22DD33EE44FF55";

	const char bin_html[] = "Stephan Müller aäöü%";
	const char hex_html[] = "Stephan%20M%C3%BCller%20a%C3%A4%C3%B6%C3%BC%25";

	char *hexstr;
	uint32_t hexstrlen;

	int ret = 0;

	(void)argc;
	(void)argv;

	hexstr = calloc(1, ((bytesize * 2) + 1));
	if (!hexstr)
		exit(1);

	bin_new = calloc(1, bytesize);
	if (!bin_new) {
		free(hexstr);
		exit(1);
	}

	bin2hex(bin, bytesize, hexstr, (bytesize * 2), 0);

	if (strncmp(hexstr, hex_l, bytesize)) {
		printf("bin2hex lower case failed (%s)\n", hexstr);
		ret++;
	}
	hex2bin(hexstr, (bytesize * 2), bin_new, bytesize);
	if (memcmp(bin, bin_new, bytesize)) {
		printf("hex2bin lower case does not produce expected output\n");
		ret++;
	}

	bin2hex(bin, bytesize, hexstr, (bytesize * 2), 1);

	if (strncmp(hexstr, hex_u, bytesize)) {
		printf("bin2hex upper case failed (%s)\n", hexstr);
		ret++;
	}
	hex2bin(hexstr, (bytesize * 2), bin_new, bytesize);
	if (memcmp(bin, bin_new, bytesize)) {
		printf("hex2bin upper case does not produce expected output\n");
		ret++;
	}

	free(hexstr);
	free(bin_new);

	if (bin2hex_html_alloc(bin_html, strlen(bin_html),
			       &hexstr, &hexstrlen)) {
		printf("invocation of bin2hex_html_alloc failed\n");
		ret++;
	} else {
		if (hexstrlen != strlen(hex_html) + 1) {
			printf("bin2hex_html_alloc return unexpected length (expected %zu, received %u)\n",
			       strlen(hex_html), hexstrlen);
			ret++;
		}

		if (strlen(hexstr) != strlen(hex_html)) {
			printf("bin2hex_html_alloc return unexpected length (expected %zu, received %zu)\n",
			       strlen(hex_html), strlen(hexstr));
			ret++;
		}

		if (strncmp(hexstr, hex_html, strlen(hex_html))) {
			printf("bin2hex_html failed (%s)\n", hexstr);
			ret++;
		}

		free(hexstr);
	}

	return ret;
}
