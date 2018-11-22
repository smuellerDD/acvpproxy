/*
 * FreeOTP
 *
 * Authors: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * Copyright (C) 2014  Nathaniel McCallum, Red Hat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "sha224.h"
#include <string.h>

void
sha224_init(hash_ctx *ctx)
{
  ctx->len = 0;
  ctx->h[0] = 0xc1059ed8;
  ctx->h[1] = 0x367cd507;
  ctx->h[2] = 0x3070dd17;
  ctx->h[3] = 0xf70e5939;
  ctx->h[4] = 0xffc00b31;
  ctx->h[5] = 0x68581511;
  ctx->h[6] = 0x64f98fa7;
  ctx->h[7] = 0xbefa4fa4;
}

void
sha224_update(hash_ctx *ctx, const void *buf, size_t len)
{
  sha256_update(ctx, buf, len);
}

void sha224_finish(hash_ctx *ctx, uint8_t *hash)
{
  uint8_t tmp[SHA256_SIZE_HASH];
  sha256_finish(ctx, tmp);
  memcpy(hash, tmp, SHA224_SIZE_HASH);
}

HASH_TYPE_DEFINE(sha224, SHA224_SIZE_HASH, SHA224_SIZE_BLOCK);
