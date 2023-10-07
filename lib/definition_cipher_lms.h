/*
 * Copyright (C) 2023 - 2023, Joachim Vandersmissen <joachim@atsec.com>
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
 * This header file defines the required data for LMS ciphers.
 * In order to define a given implementation, the following data structure must
 * be instantiated. The root of the data structure is @struct def_algo_lms.

 */

#ifndef DEFINITION_CIPHER_LMS_H
#define DEFINITION_CIPHER_LMS_H

#include "definition_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct def_algo_lms_specific_caps {
	/*
	 * A supported LMS mode that must be tested.
	 * Only one mode can be specified here.
	 *
	 * required: always
	 */
#define DEF_ALG_LMS_LMS_SHA256_M24_H5 (1 << 0)
#define DEF_ALG_LMS_LMS_SHA256_M24_H10 (1 << 1)
#define DEF_ALG_LMS_LMS_SHA256_M24_H15 (1 << 2)
#define DEF_ALG_LMS_LMS_SHA256_M24_H20 (1 << 3)
#define DEF_ALG_LMS_LMS_SHA256_M24_H25 (1 << 4)
#define DEF_ALG_LMS_LMS_SHA256_M32_H5 (1 << 5)
#define DEF_ALG_LMS_LMS_SHA256_M32_H10 (1 << 6)
#define DEF_ALG_LMS_LMS_SHA256_M32_H15 (1 << 7)
#define DEF_ALG_LMS_LMS_SHA256_M32_H20 (1 << 8)
#define DEF_ALG_LMS_LMS_SHA256_M32_H25 (1 << 9)
#define DEF_ALG_LMS_LMS_SHAKE_M24_H5 (1 << 10)
#define DEF_ALG_LMS_LMS_SHAKE_M24_H10 (1 << 11)
#define DEF_ALG_LMS_LMS_SHAKE_M24_H15 (1 << 12)
#define DEF_ALG_LMS_LMS_SHAKE_M24_H20 (1 << 13)
#define DEF_ALG_LMS_LMS_SHAKE_M24_H25 (1 << 14)
#define DEF_ALG_LMS_LMS_SHAKE_M32_H5 (1 << 15)
#define DEF_ALG_LMS_LMS_SHAKE_M32_H10 (1 << 16)
#define DEF_ALG_LMS_LMS_SHAKE_M32_H15 (1 << 17)
#define DEF_ALG_LMS_LMS_SHAKE_M32_H20 (1 << 18)
#define DEF_ALG_LMS_LMS_SHAKE_M32_H25 (1 << 19)
	unsigned int lms_mode;

	/*
	 * A supported LMOTS mode that must be tested.
	 * Only one mode can be specified here.
	 *
	 * required: always
	 */
#define DEF_ALG_LMS_LMOTS_SHA256_N24_W1 (1 << 0)
#define DEF_ALG_LMS_LMOTS_SHA256_N24_W2 (1 << 1)
#define DEF_ALG_LMS_LMOTS_SHA256_N24_W4 (1 << 2)
#define DEF_ALG_LMS_LMOTS_SHA256_N24_W8 (1 << 3)
#define DEF_ALG_LMS_LMOTS_SHA256_N32_W1 (1 << 4)
#define DEF_ALG_LMS_LMOTS_SHA256_N32_W2 (1 << 5)
#define DEF_ALG_LMS_LMOTS_SHA256_N32_W4 (1 << 6)
#define DEF_ALG_LMS_LMOTS_SHA256_N32_W8 (1 << 7)
#define DEF_ALG_LMS_LMOTS_SHAKE_N24_W1 (1 << 8)
#define DEF_ALG_LMS_LMOTS_SHAKE_N24_W2 (1 << 9)
#define DEF_ALG_LMS_LMOTS_SHAKE_N24_W4 (1 << 10)
#define DEF_ALG_LMS_LMOTS_SHAKE_N24_W8 (1 << 11)
#define DEF_ALG_LMS_LMOTS_SHAKE_N32_W1 (1 << 12)
#define DEF_ALG_LMS_LMOTS_SHAKE_N32_W2 (1 << 13)
#define DEF_ALG_LMS_LMOTS_SHAKE_N32_W4 (1 << 14)
#define DEF_ALG_LMS_LMOTS_SHAKE_N32_W8 (1 << 15)
	unsigned int lmots_mode;
};

struct def_algo_lms {
	/*
	 * LMS mode type
	 * required: always
	 */
	enum lms_mode {
		DEF_ALG_LMS_MODE_KEYGEN,
		DEF_ALG_LMS_MODE_SIGGEN,
		DEF_ALG_LMS_MODE_SIGVER,
	} lms_mode;

	/*
	 * Prerequisites to LMS
	 * required: always
	 * SHA
	 * DRBG
	 */
	const struct def_algo_prereqs *prereqvals;

	/*
	 * Number of prereqs, if 0, no entry is added to JSON
	 * Note, the prereqvals pointer above must point to the first
	 * entry of an array of prerequisites!
	 */
	unsigned int prereqvals_num;

	/**
	 * The supported LMS modes.
	 * Multiple modes can be specified here.
	 * See @struct def_algo_lms_specific_caps for valid values.
	 *
	 * required: if specific_capabilities_num = 0
	 */
	unsigned int lms_modes;

	/**
	 * The supported LMOTS modes.
	 * Multiple modes can be specified here.
	 * See @struct def_algo_lms_specific_caps for valid values.
	 *
	 * required: if specific_capabilities_num = 0
	 */
	unsigned int lmots_modes;

	/*
	 * Capabilities for all LMS/LMOTS modes that must be tested.
	 * Note that this option is mutually exclusive with lms_modes and
	 * lmots_modes above.
	 *
	 * required: if lms_modes and lmots_modes are both 0
	 */
	const struct def_algo_lms_specific_caps *specific_capabilities;

	/*
	 * Number of specific capabilities, if 0, no entry is added to JSON
	 * Note, the capabilities pointer above must point to the first
	 * entry of an array of capabilities!
	 */
	unsigned int specific_capabilities_num;
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_LMS_H */
