/*
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#ifndef _CIPHER_DEFINITIONS_H
#define _CIPHER_DEFINITIONS_H

#include "stdint.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint64_t cipher_t;

#define ACVP_CIPHERDEF		0x000fffffffffffffULL
#define ACVP_CIPHERTYPE		0xfff0000000000000ULL

#define ACVP_CIPHERTYPE_AES	0x0010000000000000ULL
#define ACVP_CIPHERTYPE_TDES	0x0020000000000000ULL
#define ACVP_CIPHERTYPE_AEAD	0x0040000000000000ULL
#define ACVP_CIPHERTYPE_HASH	0x0080000000000000ULL
#define ACVP_CIPHERTYPE_MAC	0x0100000000000000ULL
#define ACVP_CIPHERTYPE_ECC	0x0200000000000000ULL
#define ACVP_CIPHERTYPE_DRBG	0x0400000000000000ULL
#define ACVP_CIPHERTYPE_DOMAIN	0x0800000000000000ULL

/* AES, TDES, AEAD, and SHA must be allowed to be ORed */

/* AES */
#define ACVP_ECB		(ACVP_CIPHERTYPE_AES | 0x0000000000000001ULL)
#define ACVP_CBC		(ACVP_CIPHERTYPE_AES | 0x0000000000000002ULL)
#define ACVP_XTS		(ACVP_CIPHERTYPE_AES | 0x0000000000000004ULL)
#define ACVP_OFB		(ACVP_CIPHERTYPE_AES | 0x0000000000000008ULL)
#define ACVP_CFB1		(ACVP_CIPHERTYPE_AES | 0x0000000000000010ULL)
#define ACVP_CFB8		(ACVP_CIPHERTYPE_AES | 0x0000000000000020ULL)
#define ACVP_CFB128		(ACVP_CIPHERTYPE_AES | 0x0000000000000040ULL)
#define ACVP_KW			(ACVP_CIPHERTYPE_AES | 0x0000000000000080ULL)
#define ACVP_KWP		(ACVP_CIPHERTYPE_AES | 0x0000000000000100ULL)
#define ACVP_CTR		(ACVP_CIPHERTYPE_AES | 0x0000000000000200ULL)
#define ACVP_AES128		(ACVP_CIPHERTYPE_AES | 0x0000000000000400ULL)
#define ACVP_AES192		(ACVP_CIPHERTYPE_AES | 0x0000000000000800ULL)
#define ACVP_AES256		(ACVP_CIPHERTYPE_AES | 0x0000000000001000ULL)
#define ACVP_XPN		(ACVP_CIPHERTYPE_AES | 0x0000000000002000ULL)
#define ACVP_CBC_CS1		(ACVP_CIPHERTYPE_AES | 0x0000000000004000ULL)
#define ACVP_CBC_CS2		(ACVP_CIPHERTYPE_AES | 0x0000000000008000ULL)
#define ACVP_CBC_CS3		(ACVP_CIPHERTYPE_AES | 0x0000000000010000ULL)
#define ACVP_FF1		(ACVP_CIPHERTYPE_AES | 0x0000000000020000ULL)
#define ACVP_FF3_1		(ACVP_CIPHERTYPE_AES | 0x0000000000040000ULL)
#define ACVP_AESMASK		(ACVP_CIPHERTYPE_AES | 0x00000000000fffffULL)


/* TDES */
#define ACVP_TDESECB		(ACVP_CIPHERTYPE_TDES | 0x0000000000100000ULL)
#define ACVP_TDESCBC		(ACVP_CIPHERTYPE_TDES | 0x0000000000200000ULL)
#define ACVP_TDESXTS		(ACVP_CIPHERTYPE_TDES | 0x0000000000400000ULL)
#define ACVP_TDESOFB		(ACVP_CIPHERTYPE_TDES | 0x0000000000800000ULL)
#define ACVP_TDESCFB1		(ACVP_CIPHERTYPE_TDES | 0x0000000001000000ULL)
#define ACVP_TDESCFB8		(ACVP_CIPHERTYPE_TDES | 0x0000000002000000ULL)
#define ACVP_TDESCFB64		(ACVP_CIPHERTYPE_TDES | 0x0000000004000000ULL)
#define ACVP_TDESKW		(ACVP_CIPHERTYPE_TDES | 0x0000000008000000ULL)
#define ACVP_TDESCTR		(ACVP_CIPHERTYPE_TDES | 0x0000000010000000ULL)
#define ACVP_TDESCBCI		(ACVP_CIPHERTYPE_TDES | 0x0000000020000000ULL)
#define ACVP_TDESOFBI		(ACVP_CIPHERTYPE_TDES | 0x0000000040000000ULL)
#define ACVP_TDESCFBP1		(ACVP_CIPHERTYPE_TDES | 0x0000000080000000ULL)
#define ACVP_TDESCFBP8		(ACVP_CIPHERTYPE_TDES | 0x0000000100000000ULL)
#define ACVP_TDESCFBP64		(ACVP_CIPHERTYPE_TDES | 0x0000000200000000ULL)
#define ACVP_TDES		(ACVP_CIPHERTYPE_TDES | 0x0000000400000000ULL)
#define ACVP_TDESMASK		(ACVP_CIPHERTYPE_TDES | 0x0000000ffff00000ULL)

#define ACVP_SYMMASK		(ACVP_AESMASK | ACVP_TDESMASK)

#define ACVP_GCM 		(ACVP_CIPHERTYPE_AEAD | 0x0000001000000000ULL)
#define ACVP_CCM 		(ACVP_CIPHERTYPE_AEAD | 0x0000002000000000ULL)
#define ACVP_GCMSIV 		(ACVP_CIPHERTYPE_AEAD | 0x0000004000000000ULL)
#define ACVP_GMAC		(ACVP_CIPHERTYPE_AEAD | 0x0000008000000000ULL)
#define ACVP_AEADMASK		(ACVP_CIPHERTYPE_AEAD | 0x000000f000000000ULL)

/* SHA and SHAKE are allowed to be ORed together */
#define ACVP_SHA1 		(ACVP_CIPHERTYPE_HASH | 0x0000010000000000ULL)
#define ACVP_SHA224 		(ACVP_CIPHERTYPE_HASH | 0x0000020000000000ULL)
#define ACVP_SHA256 		(ACVP_CIPHERTYPE_HASH | 0x0000040000000000ULL)
#define ACVP_SHA384 		(ACVP_CIPHERTYPE_HASH | 0x0000080000000000ULL)
#define ACVP_SHA512 		(ACVP_CIPHERTYPE_HASH | 0x0000100000000000ULL)
#define ACVP_SHA512224		(ACVP_CIPHERTYPE_HASH | 0x0000200000000000ULL)
#define ACVP_SHA512256		(ACVP_CIPHERTYPE_HASH | 0x0000400000000000ULL)
#define ACVP_SHA3_224 		(ACVP_CIPHERTYPE_HASH | 0x0000800000000000ULL)
#define ACVP_SHA3_256 		(ACVP_CIPHERTYPE_HASH | 0x0001000000000000ULL)
#define ACVP_SHA3_384 		(ACVP_CIPHERTYPE_HASH | 0x0002000000000000ULL)
#define ACVP_SHA3_512 		(ACVP_CIPHERTYPE_HASH | 0x0004000000000000ULL)
#define ACVP_HASHMASK		(ACVP_CIPHERTYPE_HASH | 0x000fff0000000000ULL)

#define ACVP_SHAKE128		(ACVP_CIPHERTYPE_HASH | 0x0000000000001000ULL)
#define ACVP_SHAKE256		(ACVP_CIPHERTYPE_HASH | 0x0000000000002000ULL)
#define ACVP_SHAKEMASK		(ACVP_CIPHERTYPE_HASH | 0x000000000000f000ULL)

#define ACVP_HMACSHA1 		(ACVP_CIPHERTYPE_MAC | 0x0000000000000001ULL)
#define ACVP_HMACSHA2_224 	(ACVP_CIPHERTYPE_MAC | 0x0000000000000002ULL)
#define ACVP_HMACSHA2_256 	(ACVP_CIPHERTYPE_MAC | 0x0000000000000004ULL)
#define ACVP_HMACSHA2_384 	(ACVP_CIPHERTYPE_MAC | 0x0000000000000008ULL)
#define ACVP_HMACSHA2_512	(ACVP_CIPHERTYPE_MAC | 0x0000000000000010ULL)
#define ACVP_HMACSHA2_512224	(ACVP_CIPHERTYPE_MAC | 0x0000000000000020ULL)
#define ACVP_HMACSHA2_512256	(ACVP_CIPHERTYPE_MAC | 0x0000000000000040ULL)
#define ACVP_HMACSHA3_224 	(ACVP_CIPHERTYPE_MAC | 0x0000000000000080ULL)
#define ACVP_HMACSHA3_256 	(ACVP_CIPHERTYPE_MAC | 0x0000000000000100ULL)
#define ACVP_HMACSHA3_384 	(ACVP_CIPHERTYPE_MAC | 0x0000000000000200ULL)
#define ACVP_HMACSHA3_512	(ACVP_CIPHERTYPE_MAC | 0x0000000000000400ULL)
#define ACVP_HMACMASK		(ACVP_CIPHERTYPE_MAC | 0x0000000000000fffULL)
#define ACVP_CMAC_AES 		(ACVP_CIPHERTYPE_MAC | 0x0000000010000000ULL)
#define ACVP_CMAC_AES128	(ACVP_CIPHERTYPE_MAC | 0x0000000020000000ULL)
#define ACVP_CMAC_AES192	(ACVP_CIPHERTYPE_MAC | 0x0000000040000000ULL)
#define ACVP_CMAC_AES256	(ACVP_CIPHERTYPE_MAC | 0x0000000080000000ULL)
#define ACVP_CMAC_TDES		(ACVP_CIPHERTYPE_MAC | 0x0000000100000000ULL)
#define ACVP_CMACMASK		(ACVP_CIPHERTYPE_MAC | 0x0000000ff0000000ULL)
#define ACVP_MACMASK		(ACVP_HMACMASK | ACVP_CMACMASK)

#define ACVP_NISTP224		(ACVP_CIPHERTYPE_ECC | 0x0000000000000001ULL)
#define ACVP_NISTP256		(ACVP_CIPHERTYPE_ECC | 0x0000000000000002ULL)
#define ACVP_NISTP384		(ACVP_CIPHERTYPE_ECC | 0x0000000000000004ULL)
#define ACVP_NISTP521		(ACVP_CIPHERTYPE_ECC | 0x0000000000000008ULL)
#define ACVP_NISTK233		(ACVP_CIPHERTYPE_ECC | 0x0000000000000010ULL)
#define ACVP_NISTK283		(ACVP_CIPHERTYPE_ECC | 0x0000000000000020ULL)
#define ACVP_NISTK409		(ACVP_CIPHERTYPE_ECC | 0x0000000000000040ULL)
#define ACVP_NISTK571		(ACVP_CIPHERTYPE_ECC | 0x0000000000000080ULL)
#define ACVP_NISTB233		(ACVP_CIPHERTYPE_ECC | 0x0000000000000100ULL)
#define ACVP_NISTB283		(ACVP_CIPHERTYPE_ECC | 0x0000000000000200ULL)
#define ACVP_NISTB409		(ACVP_CIPHERTYPE_ECC | 0x0000000000000400ULL)
#define ACVP_NISTB571		(ACVP_CIPHERTYPE_ECC | 0x0000000000000800ULL)
#define ACVP_ED25519		(ACVP_CIPHERTYPE_ECC | 0x0000000000001000ULL)
#define ACVP_ED448		(ACVP_CIPHERTYPE_ECC | 0x0000000000002000ULL)
#define ACVP_NISTP192		(ACVP_CIPHERTYPE_ECC | 0x0000000000004000ULL)
#define ACVP_CURVEMASK		(ACVP_CIPHERTYPE_ECC | 0x000000000000ffffULL)

#define ACVP_ECDH 		0x0000000001000000ULL
#define ACVP_DH2048224 		0x0000000002000000ULL
#define ACVP_DH2048256		0x0000000003000000ULL
#define ACVP_RSA		0x0000000004000000ULL
#define ACVP_ECDSA		0x0000000008000000ULL
#define ACVP_DSA		0x0000000010000000ULL

#define ACVP_DRBGCTR		(ACVP_CIPHERTYPE_DRBG | 0x0000000000000001ULL)
#define ACVP_DRBGHMAC		(ACVP_CIPHERTYPE_DRBG | 0x0000000000000002ULL)
#define ACVP_DRBGHASH		(ACVP_CIPHERTYPE_DRBG | 0x0000000000000004ULL)
#define ACVP_DRBGMASK		(ACVP_CIPHERTYPE_DRBG | 0x000000000000000fULL)

#define ACVP_DH_MODP_2048	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000001ULL)
#define ACVP_DH_MODP_3072	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000002ULL)
#define ACVP_DH_MODP_4096	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000004ULL)
#define ACVP_DH_MODP_6144	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000008ULL)
#define ACVP_DH_MODP_8192	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000010ULL)
#define ACVP_DH_FFDHE_2048	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000020ULL)
#define ACVP_DH_FFDHE_3072	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000040ULL)
#define ACVP_DH_FFDHE_4096	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000080ULL)
#define ACVP_DH_FFDHE_6144	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000100ULL)
#define ACVP_DH_FFDHE_8192	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000200ULL)
#define ACVP_DH_FB		(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000400ULL)
#define ACVP_DH_FC		(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000800ULL)
#define ACVP_DH_DOMAIN_MASK	(ACVP_CIPHERTYPE_DOMAIN | 0x0000000000000fffULL)

#define ACVP_UNKNOWN		0x0000000000000000ULL

struct cipher_def_map {
	cipher_t cipher;
	const char *acvp_name;
};

static const struct cipher_def_map cipher_def_map[] = {
	{ ACVP_ECB, "ACVP-AES-ECB" },
	{ ACVP_CBC_CS1, "ACVP-AES-CBC-CS1" },
	{ ACVP_CBC_CS2, "ACVP-AES-CBC-CS2" },
	{ ACVP_CBC_CS3, "ACVP-AES-CBC-CS3" },
	{ ACVP_CBC, "ACVP-AES-CBC" },
	{ ACVP_FF1, "ACVP-AES-FF1" },
	{ ACVP_FF3_1, "ACVP-AES-FF3-1" },
	{ ACVP_XTS, "ACVP-AES-XTS" },
	{ ACVP_OFB, "ACVP-AES-OFB" },
	{ ACVP_CFB1, "ACVP-AES-CFB1" },
	{ ACVP_CFB8, "ACVP-AES-CFB8" },
	{ ACVP_CFB128, "ACVP-AES-CFB128" },
	{ ACVP_KW, "ACVP-AES-KW" },
	{ ACVP_KWP, "ACVP-AES-KWP" },
	{ ACVP_CTR, "ACVP-AES-CTR" },
	{ ACVP_AES128, "AES-128" },
	{ ACVP_AES192, "AES-192" },
	{ ACVP_AES256, "AES-256" },
	{ ACVP_XPN, "ACVP-AES-XPN" },
	{ ACVP_GMAC, "ACVP-AES-GMAC" },
	{ ACVP_GCM, "ACVP-AES-GCM" },
	{ ACVP_CCM, "ACVP-AES-CCM" },
	{ ACVP_GCMSIV, "ACVP-AES-GCM-SIV" },

	{ ACVP_TDESECB, "ACVP-TDES-ECB" },
	{ ACVP_TDESCBC, "ACVP-TDES-CBC" },
	{ ACVP_TDESOFB, "ACVP-TDES-OFB" },
	{ ACVP_TDESCFB1, "ACVP-TDES-CFB1" },
	{ ACVP_TDESCFB8, "ACVP-TDES-CFB8" },
	{ ACVP_TDESCFB64, "ACVP-TDES-CFB64" },
	{ ACVP_TDESCTR, "ACVP-TDES-CTR" },
	{ ACVP_TDESKW, "ACVP-TDES-KW" },
	{ ACVP_TDESCBCI, "ACVP-TDES-CBCI" },
	{ ACVP_TDESCFBP1, "ACVP-TDES-CFBP1" },
	{ ACVP_TDESCFBP8, "ACVP-TDES-CFBP8" },
	{ ACVP_TDESCFBP64, "ACVP-TDES-CFBP64" },
	{ ACVP_TDESOFBI, "ACVP-TDES-OFBI" },
	{ ACVP_TDES, "TDES" },

	{ ACVP_HMACSHA1, "HMAC-SHA-1" },
	{ ACVP_HMACSHA2_224, "HMAC-SHA2-224" },
	{ ACVP_HMACSHA2_256, "HMAC-SHA2-256" },
	{ ACVP_HMACSHA2_384, "HMAC-SHA2-384" },
	{ ACVP_HMACSHA2_512, "HMAC-SHA2-512" },
	{ ACVP_HMACSHA2_512224, "HMAC-SHA-512/224" },
	{ ACVP_HMACSHA2_512256, "HMAC-SHA-512/256" },
	{ ACVP_HMACSHA3_224, "HMAC-SHA3-224" },
	{ ACVP_HMACSHA3_256, "HMAC-SHA3-256" },
	{ ACVP_HMACSHA3_384, "HMAC-SHA3-384" },
	{ ACVP_HMACSHA3_512, "HMAC-SHA3-512" },

	{ ACVP_SHA1, "SHA-1" },
	{ ACVP_SHA224, "SHA2-224" },
	{ ACVP_SHA256, "SHA2-256" },
	{ ACVP_SHA384, "SHA2-384" },
	{ ACVP_SHA512, "SHA2-512" },
	{ ACVP_SHA512224, "SHA2-512/224" },
	{ ACVP_SHA512256, "SHA2-512/256" },
	{ ACVP_SHA3_224, "SHA3-224" },
	{ ACVP_SHA3_256, "SHA3-256" },
	{ ACVP_SHA3_384, "SHA3-384" },
	{ ACVP_SHA3_512, "SHA3-512" },

	{ ACVP_SHAKE128, "SHAKE-128" },
	{ ACVP_SHAKE256, "SHAKE-256" },

	{ ACVP_NISTP192, "P-192" },
	{ ACVP_NISTP224, "P-224" },
	{ ACVP_NISTP256, "P-256" },
	{ ACVP_NISTP384, "P-384" },
	{ ACVP_NISTP521, "P-521" },
	{ ACVP_NISTB233, "B-233" },
	{ ACVP_NISTB283, "B-283" },
	{ ACVP_NISTB409, "B-409" },
	{ ACVP_NISTB571, "B-571" },
	{ ACVP_NISTK233, "K-233" },
	{ ACVP_NISTK283, "K-283" },
	{ ACVP_NISTK409, "K-409" },
	{ ACVP_NISTK571, "K-571" },

	{ ACVP_ED25519, "ED-25519"},
	{ ACVP_ED448, "ED-448"},

	{ ACVP_DRBGCTR, "ctrDRBG" },
	{ ACVP_DRBGHASH, "hashDRBG" },
	{ ACVP_DRBGHMAC, "hmacDRBG" },

	{ ACVP_CMAC_AES, "CMAC-AES" },
	{ ACVP_CMAC_AES128, "CMAC-AES128" },
	{ ACVP_CMAC_AES192, "CMAC-AES192" },
	{ ACVP_CMAC_AES256, "CMAC-AES256" },
	{ ACVP_CMAC_TDES, "CMAC-TDES" },

	{ ACVP_DH_MODP_2048, "MODP-2048" },
	{ ACVP_DH_MODP_3072, "MODP-3072" },
	{ ACVP_DH_MODP_4096, "MODP-4096" },
	{ ACVP_DH_MODP_6144, "MODP-6144" },
	{ ACVP_DH_MODP_8192, "MODP-8192" },
	{ ACVP_DH_FFDHE_2048, "ffdhe2048" },
	{ ACVP_DH_FFDHE_3072, "ffdhe3072" },
	{ ACVP_DH_FFDHE_4096, "ffdhe4096" },
	{ ACVP_DH_FFDHE_6144, "ffdhe6144" },
	{ ACVP_DH_FFDHE_8192, "ffdhe8192" },
	{ ACVP_DH_FB, "FB" },
	{ ACVP_DH_FC, "FC" },
};

#ifdef __cplusplus
}
#endif

#endif /* _CIPHER_DEFINITIONS_H */
