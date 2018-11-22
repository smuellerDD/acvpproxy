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

#include "hmac.h"

#include <stdlib.h>
#include <string.h>

bool
hmac(hash_type type,
     const void *key, size_t  keylen,
     const void *msg, size_t  msglen,
     uint8_t   **out, size_t *outlen)
{
  const hash_spec *spec;
  uint8_t *block;
  uint8_t *hash;
  hash_ctx *ctx;
  size_t unused;

  spec = hash_spec_get(type);
  if (!spec)
    return false;

  block = malloc(spec->block);
  hash = malloc(spec->hash);
  ctx = malloc(spec->ctx);
  *out = malloc(spec->hash);
  *outlen = spec->hash;
  unused = spec->block;
  if (!block || !hash || !ctx || !*out) {
    free(block);
    free(hash);
    free(ctx);
    free(*out);
    return false;
  }

  if (keylen > spec->block) {
    spec->init(ctx);
    spec->update(ctx, key, keylen);
    spec->finish(ctx, block);
    unused -= spec->hash;
  } else {
    memcpy(block, key, keylen);
    unused -= keylen;
  }

  if (unused > 0)
    memset(&block[spec->block - unused], 0, unused);

  spec->init(ctx);
  for (size_t i = 0; i < spec->block; i++) {
    uint8_t b = block[i] ^ 0x36;
    spec->update(ctx, &b, 1);
  }
  spec->update(ctx, msg, msglen);
  spec->finish(ctx, hash);

  spec->init(ctx);
  for (size_t i = 0; i < spec->block; i++) {
    uint8_t b = block[i] ^ 0x5c;
    spec->update(ctx, &b, 1);
  }
  spec->update(ctx, hash, spec->hash);
  spec->finish(ctx, *out);

  free(block);
  free(hash);
  free(ctx);
  return true;
}
