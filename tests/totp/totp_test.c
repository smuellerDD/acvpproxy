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

#include "../../lib/common/totp.c"

/*
 * SHA-256 TOTP test vectors.
 */
static int hotp_sha256(void)
{
	/* HOTP test vectors from RFC 4226 */
	uint8_t hmac256_key[] = "\x31\x32\x33\x34\x35\x36\x37\x38"
				"\x39\x30\x31\x32\x33\x34\x35\x36"
				"\x37\x38\x39\x30\x31\x32\x33\x34"
				"\x35\x36\x37\x38\x39\x30\x31\x32";
	uint64_t time[] = { 59, 1111111109, 1111111111, 1234567890, 2000000000,
			    20000000000 };
	unsigned int totp_sha256[] = { 46119246, 68084774, 67062674, 91819424,
				       90698825, 77737706 };

	int ret, result = 0;
	unsigned int i;
	uint32_t totp_val;

	for (i = 0; i < 6; i++) {
		uint64_t counter = time[i] / 30;

		ret = hotp(hmac256_key, sizeof(hmac256_key) - 1, counter, 8,
			   &totp_val);
		if (ret) {
			printf("totp failure %d\n", ret);
			result++;
			continue;
		}

		if (totp_val == totp_sha256[i]) {
			printf("SHA-256 Test PASS for counter %u\n", i);
		} else {
			printf("SHA-256 Test FAIL for counter %u (exp %u, calc %u)\n",
			       i, totp_sha256[i], totp_val);
			result++;
		}
	}

	ret = _totp(hmac256_key, sizeof(hmac256_key) - 1, 30, 6, &totp_val);
	if (ret) {
		printf("Test FAIL for totp %u\n", totp_val);
	} else {
		printf("Test PASS for totp %u\n", totp_val);
	}

	return result;
}

#if 0
/*
 * SHA-1 HOTP test vectors.
 */
static int hotp_sha1(void)
{
	/* HOTP test vectors from RFC 4226 */
	uint8_t hmac_key[] = "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30"
			     "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30";
	uint32_t hotp_exp[] = { 755224, 287082, 359152, 969429, 338314,
				254676, 287922, 162583, 399871, 520489 };
	uint64_t counter;
	uint32_t totp_val;
	int ret, result = 0;

	for (counter = 0; counter < 10; counter++) {
		uint32_t hotp_val;

		ret = hotp(hmac_key, sizeof(hmac_key) - 1, counter, 6,
			   &hotp_val);
		if (ret) {
			printf("hotp failure %d\n", ret);
			result++;
			continue;
		}

		if (hotp_val == hotp_exp[counter]) {
			printf("SHA-1 Test PASS for counter %lu\n", counter);
		} else {
			printf("SHA-1 Test FAIL for counter %lu (exp %u, calc %u)\n",
			       counter, hotp_exp[counter], hotp_val);
			result++;
		}
	}

	ret = _totp(hmac_key, sizeof(hmac_key) - 1, 30, 6, &totp_val);
	if (ret) {
		printf("Test FAIL for totp %u\n", totp_val);
	} else {
		printf("Test PASS for totp %u\n", totp_val);
	}

	return result;
}
#endif

int main(int argc, char *argv[])
{
	int ret = hotp_sha256();

	(void)argc;
	(void)argv;

	if (ret < 0)
		return ret;

	return 0;
}
