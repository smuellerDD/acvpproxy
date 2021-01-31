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

#ifndef HMAC_H
#define HMAC_H

#include "hash.h"
#include "sha3.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define SHA_MAX_SIZE_BLOCK	SHA3_MAX_SIZE_BLOCK
#define SHA_MAX_SIZE_DIGEST	64

/**
 * @brief Calculate HMAC
 *
 * @param hash [in] Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param key [in] MAC key of arbitrary size
 * @param keylen [in] Size of the MAC key
 * @param in [in] Buffer holding the data whose MAC shall be calculated
 * @param inlen [in] Length of the input buffer
 * @param mac [out] Buffer with at least the size of the message digest.
 *
 * The HMAC calculation operates entirely on the stack.
 */
void hmac(const struct hash *hash, const uint8_t *key, size_t keylen,
	  const uint8_t *in, size_t inlen, uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif /* HMAC_H */
