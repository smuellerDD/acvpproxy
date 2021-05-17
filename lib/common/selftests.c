/*
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
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

#include "constructor.h"
#include "hash/hmac.h"
#include "hash/sha256.h"
#include "hash/sha512.h"
#include "hash/sha3.h"
#include "logger.h"

static int compare(const uint8_t *act, const uint8_t *exp, const size_t len,
		   const char *info)
{
	if (memcmp(act, exp, len)) {
		unsigned int i;

		printf("Expected %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(exp + i));

		printf("\n");

		printf("Actual %s ", info);
		for (i = 0; i < len; i++)
			printf("0x%.2x ", *(act + i));

		printf("\n");

		return 1;
	}

	return 0;
}

static int sha3_tester(void)
{
	HASH_CTX_ON_STACK(ctx);
	static const uint8_t msg_224[] = { 0x50, 0xEF, 0x73 };
	static const uint8_t exp_224[] = { 0x42, 0xF9, 0xE4, 0xEA, 0xE8, 0x55,
					   0x49, 0x61, 0xD1, 0xD2, 0x7D, 0x47,
					   0xD9, 0xAF, 0x08, 0xAF, 0x98, 0x8F,
					   0x18, 0x9F, 0x53, 0x42, 0x2A, 0x07,
					   0xD8, 0x7C, 0x68, 0xC1 };
	static const uint8_t msg_256[] = { 0x5E, 0x5E, 0xD6 };
	static const uint8_t exp_256[] = { 0xF1, 0x6E, 0x66, 0xC0, 0x43, 0x72,
					   0xB4, 0xA3, 0xE1, 0xE3, 0x2E, 0x07,
					   0xC4, 0x1C, 0x03, 0x40, 0x8A, 0xD5,
					   0x43, 0x86, 0x8C, 0xC4, 0x0E, 0xC5,
					   0x5E, 0x00, 0xBB, 0xBB, 0xBD, 0xF5,
					   0x91, 0x1E };
	static const uint8_t msg_384[] = { 0xE7, 0x3B, 0xAD };
	static const uint8_t exp_384[] = { 0xc4, 0x02, 0xc8, 0x29, 0x90, 0x68,
					   0xaa, 0x30, 0x28, 0xa9, 0xa4, 0x1c,
					   0xff, 0x9a, 0x0b, 0x74, 0x27, 0x31,
					   0x92, 0x70, 0xf2, 0x42, 0x18, 0xda,
					   0xe8, 0x68, 0x1a, 0x89, 0x01, 0x51,
					   0x0c, 0x47, 0x5a, 0x5f, 0xb9, 0x6b,
					   0x5c, 0xbc, 0x32, 0xdc, 0xa1, 0x5f,
					   0x28, 0x53, 0xa0, 0xce, 0x55, 0xf6 };
	static const uint8_t msg_512[] = { 0x82, 0xD9, 0x19 };
	static const uint8_t exp_512[] = { 0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5,
					   0x0A, 0x67, 0xFE, 0x69, 0xBD, 0x3F,
					   0xCE, 0xFE, 0x12, 0xE7, 0x1D, 0xE0,
					   0x4F, 0xA2, 0x51, 0xC6, 0x7E, 0x9C,
					   0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC,
					   0x89, 0xCA, 0x9B, 0x28, 0x88, 0x3B,
					   0x2A, 0xDB, 0x22, 0x84, 0x69, 0x5D,
					   0xD0, 0x43, 0x77, 0x55, 0x32, 0x19,
					   0xC8, 0xFD, 0x07, 0xA9, 0x4C, 0x29,
					   0xD7, 0x46, 0xCC, 0xEF, 0xB1, 0x09,
					   0x6E, 0xDE, 0x42, 0x91 };
	uint8_t act[SHA3_512_SIZE_DIGEST];
	int ret;

	sha3_224->init(ctx);
	sha3_224->update(ctx, msg_224, 3);
	sha3_224->final(ctx, act);
	ret = compare(act, exp_224, SHA3_224_SIZE_DIGEST, "SHA3-224");

	sha3_256->init(ctx);
	sha3_256->update(ctx, msg_256, 3);
	sha3_256->final(ctx, act);
	ret += compare(act, exp_256, SHA3_256_SIZE_DIGEST, "SHA3-256");

	sha3_384->init(ctx);
	sha3_384->update(ctx, msg_384, 3);
	sha3_384->final(ctx, act);
	ret += compare(act, exp_384, SHA3_384_SIZE_DIGEST, "SHA3-384");

	sha3_512->init(ctx);
	sha3_512->update(ctx, msg_512, 3);
	sha3_512->final(ctx, act);
	ret += compare(act, exp_512, SHA3_512_SIZE_DIGEST, "SHA3-512");

	return ret;
}

static int sha3_hmac_tester(void)
{
	static const uint8_t msg_224[] = { 0x35, 0x8E, 0x06, 0xBA, 0x03, 0x21,
					   0x83, 0xFC, 0x18, 0x20, 0x58, 0xBD,
					   0xB7, 0xBB, 0x13, 0x40 };
	static const uint8_t key_224[] = { 0xBB, 0x00, 0x95, 0xC4, 0xA4, 0xA6,
					   0x67, 0xD2, 0xE7, 0x43, 0x30, 0xE5,
					   0xD6 };
	static const uint8_t exp_224[] = { 0x16, 0xf7, 0xb2, 0x7e, 0x25, 0x37,
					   0x6c, 0x38, 0xcf, 0xaa, 0x6f, 0xcc,
					   0xe2, 0x85, 0xc5, 0x14, 0x28, 0xdb,
					   0x33, 0xa0, 0xfe, 0x7a, 0xf0, 0xaf,
					   0x53, 0x95, 0xde, 0xa2 };
	uint8_t act[SHA3_512_SIZE_DIGEST];
	int ret;

	hmac(sha3_224, key_224, 13, msg_224, 16, act);
	ret = compare(act, exp_224, SHA3_224_SIZE_DIGEST, "HMAC SHA3-224");

	return ret;
}

static int sha_tester(void)
{
	HASH_CTX_ON_STACK(ctx);
	static const uint8_t msg_256[] = { 0x06, 0x3A, 0x53 };
	static const uint8_t exp_256[] = { 0x8b, 0x05, 0x65, 0x59, 0x60, 0x71,
					   0xc7, 0x6e, 0x35, 0xe1, 0xea, 0x54,
					   0x48, 0x39, 0xe6, 0x47, 0x27, 0xdf,
					   0x89, 0xb4, 0xde, 0x27, 0x74, 0x44,
					   0xa7, 0x7f, 0x77, 0xcb, 0x97, 0x89,
					   0x6f, 0xf4 };
	static const uint8_t msg_512[] = { 0x7F, 0xAD, 0x12 };
	static const uint8_t exp_512[] = { 0x53, 0x35, 0x98, 0xe5, 0x29, 0x49,
					   0x18, 0xa0, 0xaf, 0x4b, 0x3a, 0x62,
					   0x31, 0xcb, 0xd7, 0x19, 0x21, 0xdb,
					   0x80, 0xe1, 0x00, 0xa0, 0x74, 0x95,
					   0xb4, 0x44, 0xc4, 0x7a, 0xdb, 0xbc,
					   0x9a, 0x64, 0x76, 0xbb, 0xc8, 0xdb,
					   0x8e, 0xe3, 0x0c, 0x87, 0x2f, 0x11,
					   0x35, 0xf1, 0x64, 0x65, 0x9c, 0x52,
					   0xce, 0xc7, 0x7c, 0xcf, 0xb8, 0xc7,
					   0xd8, 0x57, 0x63, 0xda, 0xee, 0x07,
					   0x9f, 0x60, 0x0c, 0x79 };
	uint8_t act[SHA512_SIZE_DIGEST];
	int ret;

	sha256->init(ctx);
	sha256->update(ctx, msg_256, 3);
	sha256->final(ctx, act);
	ret = compare(act, exp_256, SHA256_SIZE_DIGEST, "SHA-256");

	sha512->init(ctx);
	sha512->update(ctx, msg_512, 3);
	sha512->final(ctx, act);
	ret += compare(act, exp_512, SHA512_SIZE_DIGEST, "SHA-512");

	return ret;
}

static int crypto_selftest(void)
{
	int ret = sha3_tester();

	ret += sha3_hmac_tester();
	ret += sha_tester();

	if (ret) {
		logger_set_verbosity(LOGGER_ERR);
		logger(LOGGER_ERR, LOGGER_C_ANY,
		       "Cryptographic power-up self tests failed\n");
	}

	return ret;
}

ACVP_DEFINE_CONSTRUCTOR(acvp_selftests)
static void acvp_selftests(void)
{
	int ret = crypto_selftest();

	if (ret)
		exit(ret);
}
