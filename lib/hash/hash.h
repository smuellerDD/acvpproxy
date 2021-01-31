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

#ifndef HASH_H
#define HASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct sha_ctx;
struct hash {
	void (*init)(struct sha_ctx *ctx);
	void (*update)(struct sha_ctx *ctx, const uint8_t *in, size_t inlen);
	void (*final)(struct sha_ctx *ctx, uint8_t *digest);
	unsigned int blocksize;
	unsigned int digestsize;
	unsigned int ctxsize;
};

#define SHA_MAX_CTX_SIZE	368
#define HASH_CTX_ON_STACK(name)						\
	uint8_t name ## _ctx_buf[SHA_MAX_CTX_SIZE];			\
	struct sha_ctx *name = (struct sha_ctx *) name ## _ctx_buf

#ifdef __cplusplus
}
#endif

#endif /* HASH_H */
