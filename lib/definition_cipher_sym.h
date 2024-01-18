/*
* Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

/**
 * This header file defines the required data for symmetric ciphers including
 * AEAD ciphers. In order to define a given implementation, the following data
 * structures must be instantiated. The root of the data structures is
 * @struct def_algo_sym. Please start from this data structure and fill in the
 * required field for the requested type of symmetric / AEAD cipher
 * implementation.
 */

#ifndef DEFINITION_CIPHER_SYM_H
#define DEFINITION_CIPHER_SYM_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * AES-FF1 and AES-FF3-1 capability data
 ****************************************************************************/
struct def_algo_sym_aes_ff {
	/*
	 * An alphabet the IUT supports for Format Preserving Encryption.
	 * Example "0123456789abcdefghijklmnopqrstuvwxyz". Alphabets should be
	 * a minimum of two characters, and a maximum of 62 (all numbers and
	 * upper and lower case letters).
	 *
	 * required: always
	 */
	const char *alphabet;

	/*
	 * The number base for this capability, should match the number of
	 * characters from the alphabet.
	 *
	 * min: 2
	 * max 62
	 *
	 * required: always
	 */
	int radix;

	/*
	 * The minimum payload length the IUT can support for this alphabet.
	 *
	 * min: 2
	 * max: maxlen
	 *
	 * required: always
	 */
	int minlen;

	/*
	 * The maximum payload length the IUT can support for this alphabet.
	 *
	 * min: minlen
	 * max: variable calculation based on radix and algorithm, see
	 *      [SP800-38Gr1].
	 *
	 * required: always
	 */
	int maxlen;
};

/****************************************************************************
 * Symmetric cipher  common data
 ****************************************************************************/
/*
 * Symmetric ciphers of AES and TDES, including AEAD ciphers
 */
struct def_algo_sym {
	/*
	 * AES-ECB
	 * AES-CBC
	 * AES-CBC_CS1
	 * AES-CBC_CS2
	 * AES-CBC_CS3
	 * AES-FF1
	 * AES-FF3-1
	 * AES-OFB
	 * AES-CFB1
	 * AES-CFB8
	 * AES-CFB128
	 * AES-CTR
	 * AES-GCM
	 * AES-GMAC
	 * AES-XPN
	 * AES-CCM
	 * AES-XTS
	 * AES-KW
	 * AES-KWP
	 * TDES-ECB
	 * TDES-CBC
	 * TDES-CBC-I
	 * TDES-CFB1
	 * TDES-CFB8
	 * TDES-CFB64
	 * TDES-CFB-P1
	 * TDES-CFB-P8
	 * TDES-CFB-P64
	 * TDES-OFB
	 * TDES-OFB-I
	 * TDES-CTR
	 * TDES-KW
	 * required: always
	 */
	cipher_t algorithm;

	/*
	 * Prerequisites to cipher test
	 * required for the following ciphers:
	 * AES-GCM: AES-ECB, DRBG
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/*
	 * Supported direction
	 * required: always
	 */
#define DEF_ALG_SYM_DIRECTION_ENCRYPTION (1 << 0)
#define DEF_ALG_SYM_DIRECTION_DECRYPTION (1 << 1)
	unsigned int direction;

	/*
	 * Key length in bits
	 * required: always
	 */
#define DEF_ALG_SYM_KEYLEN_128 (1 << 0)
#define DEF_ALG_SYM_KEYLEN_168 (1 << 1)
#define DEF_ALG_SYM_KEYLEN_192 (1 << 2)
#define DEF_ALG_SYM_KEYLEN_256 (1 << 3)
	unsigned int keylen;

	/*
	 * Supported plaintext length in bits:
	 * * general: between 0 and 65536
	 * * AES-CCM: between 0 and 256 in 8 bit increments
	 * * AES-GCM: zero / two values divisible by 128,
	 *	      zero / two values not divisible by 128
	 * * AES-XTS: zero / two values divisible by 128,
	 *	      zero / two values not divisible by 128,
	 *	      maximum data length not to exceed 2^20
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: always
	 */
	int ptlen[DEF_ALG_MAX_INT];

	/*
	 * IV/Nonce length in bits (optional):
	 * * general: between 8 and 1024 bits
	 * * AES-CCM: between 56 and 104 in 8 bit increments (7 and 13 bytes)
	 * * AES-GCM: up to 3 values between 8 and 1024 bits
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: only for all modes, except AES-ECB, TDES-ECB, AES-XTS
	 */
	int ivlen[DEF_ALG_MAX_INT];

	/*
	 * AEAD IV generation mode
	 * required: only for AES-GCM mode
	 */
	enum ivgen {
		DEF_ALG_SYM_IVGEN_UNDEF = 0,
		DEF_ALG_SYM_IVGEN_INTERNAL,
		DEF_ALG_SYM_IVGEN_EXTERNAL,
	} ivgen;

	/*
	 * AEAD IV generation mode
	 * required: only for AES-GCM mode
	 */
	enum ivgenmode {
		DEF_ALG_SYM_IVGENMODE_UNDEF = 0,
		DEF_ALG_SYM_IVGENMODE_821,
		DEF_ALG_SYM_IVGENMODE_822,
	} ivgenmode;

	/*
	 * Salt generation method for AES-XPN mode only.
	 * required: only for AES-XPN mode
	 */
	enum saltgen {
		DEF_ALG_SYM_SALTGEN_UNDEF = 0,
		DEF_ALG_SYM_SALTGEN_INTERNAL,
		DEF_ALG_SYM_SALTGEN_EXTERNAL,
	} saltgen;

	/*
	 * AEAD AAD length in bits
	 * * general: 0 - 65536
	 * * AES-CCM: range between 0 and 2^16 * 8
	 * * AES-GCM: array of two values divisible by 128 (if supported) and
	 *	      two values not divisible by 128
	 * Note: any value equal to 0 implies that JSON entry is not generated.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: only for AES-CCM or AES-GCM modes
	 */
	int aadlen[DEF_ALG_MAX_INT];

	/*
	 * AEAD tag length in bits
	 * * AES-CCM: between 32 and 128 bits in 16 bits increments
	 * * AES-GCM: between 32 and 128 bits in 16 bits increments
	 * Note: a value of 0 implies that JSON entry is not generated.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: only for AES-CCM or AES-GCM modes
	 */
	int taglen[DEF_ALG_MAX_INT];

	/*
	 * AES SP800-38F KW cipher type (regular or inverse)
	 * required: only for AES-KW mode
	 */
#define DEF_ALG_SYM_KW_CIPHER (1 << 0)
#define DEF_ALG_SYM_KW_INVERSE (1 << 1)
	unsigned int kwcipher;

	/*
	 * The format of tweak value for AES-XTS
	 * required: unused in current ACVP
	 */
#define DEF_ALG_SYM_XTS_TWEAK_128HEX (1 << 0)
#define DEF_ALG_SYM_XTS_TWEAK_DUSEQUENCE (1 << 1)
	unsigned int tweakformat;

	/*
	 * The representation of the tweak value for AES-XTS with the
	 * following types:
	 *	* HEX refers to a 128-bit hexadecimal string used as a tweak
	 *	  value, and
	 *	* NUM refers to a data unit sequence number (integer) used as
	 *	  a tweak value.
	 * required: only for AES-XTS mode
	 */
#define DEF_ALG_SYM_XTS_TWEAK_HEX (1 << 0)
#define DEF_ALG_SYM_XTS_TWEAK_NUM (1 << 1)
	unsigned int tweakmode;

	/*
	 * XTS data unit length
	 *
	 * The length must be between 128 and 65536 (bits)
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * Without this option, the test vectors will always have the same
	 * data unit length as the payload.
	 *
	 * required: optional for XTS
	 */
	int xts_data_unit_len[DEF_ALG_MAX_INT];

	/*
	 * unused
	 */
	bool xts_data_unit_len_matches_payload;

	/*
	 * Source of AES-CTR mode
	 * required: not used any more by ACVP
	 */
	enum ctrsource {
		DEF_ALG_SYM_CTR_UNDEF = 0,
		DEF_ALG_SYM_CTR_INTERNAL,
		DEF_ALG_SYM_CTR_EXTERNAL
	} ctrsource;

	/*
	 * Is overflow of counter handled?
	 * required: only for AES-CTR mode
	 */
	enum ctroverflow {
		DEF_ALG_SYM_CTROVERFLOW_UNDEF = 0,
		DEF_ALG_SYM_CTROVERFLOW_HANDLED,
		DEF_ALG_SYM_CTROVERFLOW_UNHANDLED
	} ctroverflow;

	/*
	 * Is the counter incremented or decremented.
	 *
	 * Note, if the CTR testing is disabled (e.g. when using an LFSR for
	 * the counter update), the validation report must provide an argument
	 * why there is no reuse of a counter value.
	 *
	 * required: only for AES-CTR mode
	 */
	enum ctrincrement {
		DEF_ALG_SYM_CTRINCREMENT_UNDEF = 0,
		DEF_ALG_SYM_CTRINCREMENT_INCREMENT,
		DEF_ALG_SYM_CTRINCREMENT_DECREMENT,
		DEF_ALG_SYM_CTRINCREMENT_DISABLE, /** Disable of CTR tests */
	} ctrincrement;

	/*
	 * The domain of values allowed for ACVP-AES-FF1's tweak value.
	 * Allowed range is 0-128 bits mod 8.
	 *
	 * You may define a range with DEF_ALG_DOMAIN.
	 *
	 * required: only for AES-FF1 and AES-FF3-1
	 */
	int tweaklen[DEF_ALG_MAX_INT];

	/*
	 * Specify the conformance claim for a given cipher
	 *
	 * DEF_ALG_SYM_CONFORMANCE_RFC3686: ACVP-AES-CTR conformance "RFC3686".
	 * This conformance ensures the IV is generated with the LSB[32] of the
	 * IV representing the integer "1".
	 *
	 * required: optional
	 */
#define DEF_ALG_SYM_CONFORMANCE_RFC3686 (1 << 0)
	unsigned int conformance;

	/*
	 * Specific capabilities for the AES-FF1 and AES-FF3-1 cipher.
	 *
	 * required: only for AES-FF1 and AES-FF3-1
	 */
	union {
		const struct def_algo_sym_aes_ff *aes_ff;
	} capabilities;

	/*
	 * Number of capabilities, if 0, no entry is added to JSON
	 * Note, the capabilities pointer above must point to the first
	 * entry of an array of capabilities!
	 */
	unsigned int capabilities_num;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_SYM_H */
