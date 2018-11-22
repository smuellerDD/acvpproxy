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

#include "sha384.h"
#include <string.h>

void
sha384_init(hash_ctx *ctx)
{
  ctx->len = 0;
  ctx->h[0] = 0xcbbb9d5dc1059ed8ULL;
  ctx->h[1] = 0x629a292a367cd507ULL;
  ctx->h[2] = 0x9159015a3070dd17ULL;
  ctx->h[3] = 0x152fecd8f70e5939ULL;
  ctx->h[4] = 0x67332667ffc00b31ULL;
  ctx->h[5] = 0x8eb44a8768581511ULL;
  ctx->h[6] = 0xdb0c2e0d64f98fa7ULL;
  ctx->h[7] = 0x47b5481dbefa4fa4ULL;
}

void
sha384_update(hash_ctx *ctx, const void *buf, size_t len)
{
  sha512_update(ctx, buf, len);
}

void
sha384_finish(hash_ctx *ctx, uint8_t *hash)
{
  uint8_t tmp[SHA512_SIZE_HASH];
  sha512_finish(ctx, tmp);
  memcpy(hash, tmp, SHA384_SIZE_HASH);
}

HASH_TYPE_DEFINE(sha384, SHA384_SIZE_HASH, SHA384_SIZE_BLOCK);
