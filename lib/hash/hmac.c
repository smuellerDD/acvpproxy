/* Generic HMAC implementation
 *
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

#include <stdint.h>
#include <string.h>

#include "hmac.h"
#include "memset_secure.h"

#define IPAD	0x36
#define OPAD	0x5c

void hmac(const struct hash *hash, const uint8_t *key, size_t keylen,
	  const uint8_t *in, size_t inlen, uint8_t *mac)
{
	HASH_CTX_ON_STACK(ctx);
	uint8_t k0[SHA_MAX_SIZE_BLOCK], k0_ipad[SHA_MAX_SIZE_BLOCK];
	unsigned int i;

	if (hash->ctxsize > SHA_MAX_CTX_SIZE ||
	    hash->blocksize > SHA_MAX_SIZE_BLOCK ||
	    hash->digestsize > SHA_MAX_SIZE_DIGEST)
		return;

	if (keylen > hash->blocksize) {
		hash->init(ctx);
		hash->update(ctx, key, keylen);
		hash->final(ctx, k0);
		memset(k0 + hash->digestsize, 0,
		       hash->blocksize - hash->digestsize);
	} else {
		memcpy(k0, key, keylen);
		memset(k0 + keylen, 0, hash->blocksize - keylen);
	}

	for (i = 0; i < hash->blocksize; i++)
		k0_ipad[i] = k0[i] ^ IPAD;

	hash->init(ctx);
	hash->update(ctx, k0_ipad, hash->blocksize);
	hash->update(ctx, in, inlen);
	hash->final(ctx, mac);

	for (i = 0; i < hash->blocksize; i++)
		k0[i] ^= OPAD;

	hash->init(ctx);
	hash->update(ctx, k0, hash->blocksize);
	hash->update(ctx, mac, hash->digestsize);
	hash->final(ctx, mac);

	memset_secure(k0, 0, hash->blocksize);
	memset_secure(k0_ipad, 0, hash->blocksize);
}
