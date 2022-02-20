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

#ifndef TOTP_H
#define TOTP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TOTP protocol implementation according to RFC6238
 *
 * This implementation uses the following parameters: step size of the time
 * is 30 seconds and the size of the produced digit is TOTP_NUMBER_DIGITS
 * digits (between 0 and 1,000,000). It uses HMAC with the hash type
 * TOTP_HASH_TYPE.
 *
 * Note, it is vital that the time between the current system and the remote
 * system is synchronized.
 *
 * @param totp_val [out] TOPT value.
 *
 * @return 0 on success, < 0 on error
 */
int totp(uint32_t *totp_val);

/**
 * @brief Set TOTP seed value
 *
 * @param K [in] Secret K as specified in RFC4226 that is shared between both
 *		 parties.
 * @param Klen [in] Size of the buffer holding K.
 * @param last_gen [in] Time stamp when TOTP value was generated last time. It
 *			is permissible to set it to 0 in case TOTP was never
 *			used.
 * @param production [in] Indicator whether the production or demo server
 *			  will be accessed
 * @param last_gen_cb [in] Callback to be invoked when a TOTP value is generated
 *			   to allow a framework to store the current time
 *			   for potential later initialization. This function
 *			   may be NULL if no callback is requested.
 * @return 0 on success, < 0 on error
 */
int totp_set_seed(const uint8_t *K, size_t Klen, time_t last_gen,
		  bool production, void (*last_gen_cb)(const time_t now));

/**
 * @brief release the seed data
 */
void totp_release_seed(void);

/**
 * @brief terminate any pending generation operations without releasing
 *	  the seed.
 */
void totp_term(void);

#define TOTP_HASH_TYPE HASH_TYPE_SHA256
#ifndef TOTP_STEP_SIZE
#define TOTP_STEP_SIZE 30
#endif
#define TOTP_NUMBER_DIGITS 8

/****************************************************************************
 * Internal API for TOTP server
 ****************************************************************************/
int totp_get_val(uint32_t *totp_val);

#ifdef __cplusplus
}
#endif

#endif /* TOTP_H */
