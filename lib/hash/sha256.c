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

/* This file adapted from: http://port70.net/~nsz/crypt/ */
/* Original code public domain sha256 implementation based on fips180-3 */
#include "sha256.h"
#include <string.h>

static uint32_t ror(uint32_t n, int k) { return (n >> k) | (n << (32-k)); }
#define Ch(x,y,z)  (z ^ (x & (y ^ z)))
#define Maj(x,y,z) ((x & y) | (z & (x | y)))
#define S0(x)      (ror(x,2) ^ ror(x,13) ^ ror(x,22))
#define S1(x)      (ror(x,6) ^ ror(x,11) ^ ror(x,25))
#define R0(x)      (ror(x,7) ^ ror(x,18) ^ (x>>3))
#define R1(x)      (ror(x,17) ^ ror(x,19) ^ (x>>10))

static const uint32_t K[] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void
processblock(hash_ctx *ctx, const uint8_t *buf)
{
  uint32_t W[64], t1, t2, a, b, c, d, e, f, g, h;
  int i;

  for (i = 0; i < 16; i++) {
    W[i]  = (uint32_t) buf[4 * i + 0] << 24;
    W[i] |= (uint32_t) buf[4 * i + 1] << 16;
    W[i] |= (uint32_t) buf[4 * i + 2] << 8;
    W[i] |= buf[4 * i + 3];
  }

  for (; i < 64; i++)
    W[i] = R1(W[i-2]) + W[i - 7] + R0(W[i - 15]) + W[i - 16];

  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];
  f = ctx->h[5];
  g = ctx->h[6];
  h = ctx->h[7];

  #define ROUND(a,b,c,d,e,f,g,h,i) \
		t1 = h + S1(e) + Ch(e,f,g) + K[i] + W[i]; \
		t2 = S0(a) + Maj(a,b,c); \
		d += t1; \
		h = t1 + t2;
  for (i = 0; i < 64;) {
    ROUND(a, b, c, d, e, f, g, h, i); i++;
    ROUND(h, a, b, c, d, e, f, g, i); i++;
    ROUND(g, h, a, b, c, d, e, f, i); i++;
    ROUND(f, g, h, a, b, c, d, e, i); i++;
    ROUND(e, f, g, h, a, b, c, d, i); i++;
    ROUND(d, e, f, g, h, a, b, c, i); i++;
    ROUND(c, d, e, f, g, h, a, b, i); i++;
    ROUND(b, c, d, e, f, g, h, a, i); i++;
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
  ctx->h[5] += f;
  ctx->h[6] += g;
  ctx->h[7] += h;
}

static void
pad(hash_ctx *ctx)
{
  unsigned r = ctx->len % 64;

  ctx->buf[r++] = 0x80;
  if (r > 56) {
    memset(ctx->buf + r, 0, 64 - r); r = 0;
    processblock(ctx, ctx->buf);
  }

  memset(ctx->buf + r, 0, 56 - r);

  ctx->len *= 8;
  ctx->buf[56] = ctx->len >> 56;
  ctx->buf[57] = ctx->len >> 48;
  ctx->buf[58] = ctx->len >> 40;
  ctx->buf[59] = ctx->len >> 32;
  ctx->buf[60] = ctx->len >> 24;
  ctx->buf[61] = ctx->len >> 16;
  ctx->buf[62] = ctx->len >> 8;
  ctx->buf[63] = ctx->len;

  processblock(ctx, ctx->buf);
}

void
sha256_init(hash_ctx *ctx)
{
  ctx->len = 0;
  ctx->h[0] = 0x6a09e667;
  ctx->h[1] = 0xbb67ae85;
  ctx->h[2] = 0x3c6ef372;
  ctx->h[3] = 0xa54ff53a;
  ctx->h[4] = 0x510e527f;
  ctx->h[5] = 0x9b05688c;
  ctx->h[6] = 0x1f83d9ab;
  ctx->h[7] = 0x5be0cd19;
}

void
sha256_update(hash_ctx *ctx, const void *buf, size_t len)
{
  const uint8_t *p = buf;
  unsigned r = ctx->len % 64;

  ctx->len += len;
  if (r) {
    if (len < 64 - r) {
      memcpy(ctx->buf + r, p, len);
      return;
    }

    memcpy(ctx->buf + r, p, 64 - r);

    len -= 64 - r;
    p += 64 - r;

    processblock(ctx, ctx->buf);
  }

  for (; len >= 64; len -= 64, p += 64)
    processblock(ctx, p);

  memcpy(ctx->buf, p, len);
}

void
sha256_finish(hash_ctx *ctx, uint8_t *hash)
{
  int i;

  pad(ctx);
  for (i = 0; i < 8; i++) {
    hash[4 * i + 0] = ctx->h[i] >> 24;
    hash[4 * i + 1] = ctx->h[i] >> 16;
    hash[4 * i + 2] = ctx->h[i] >> 8;
    hash[4 * i + 3] = ctx->h[i];
  }
}

HASH_TYPE_DEFINE(sha256, SHA256_SIZE_HASH, SHA256_SIZE_BLOCK);
