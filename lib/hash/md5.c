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
/* Original code public domain md5 implementation based on rfc1321 and libtomcrypt */
#include "md5.h"
#include <string.h>

static uint32_t rol(uint32_t n, int k) { return (n << k) | (n >> (32-k)); }
#define F(x,y,z) (z ^ (x & (y ^ z)))
#define G(x,y,z) (y ^ (z & (y ^ x)))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))
#define FF(a,b,c,d,w,s,t) a += F(b,c,d) + w + t; a = rol(a,s) + b
#define GG(a,b,c,d,w,s,t) a += G(b,c,d) + w + t; a = rol(a,s) + b
#define HH(a,b,c,d,w,s,t) a += H(b,c,d) + w + t; a = rol(a,s) + b
#define II(a,b,c,d,w,s,t) a += I(b,c,d) + w + t; a = rol(a,s) + b

static const uint32_t tab[] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static void
processblock(hash_ctx *ctx, const uint8_t *buf)
{
  uint32_t i, W[16], a, b, c, d;

  for (i = 0; i < 16; i++) {
    W[i]  = (uint32_t) buf[4 * i + 0];
    W[i] |= (uint32_t) buf[4 * i + 1] << 8;
    W[i] |= (uint32_t) buf[4 * i + 2] << 16;
    W[i] |= (uint32_t) buf[4 * i + 3] << 24;
  }

  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];

  i = 0;

  while (i < 16) {
    FF(a, b, c, d, W[i],  7, tab[i]); i++;
    FF(d, a, b, c, W[i], 12, tab[i]); i++;
    FF(c, d, a, b, W[i], 17, tab[i]); i++;
    FF(b, c, d, a, W[i], 22, tab[i]); i++;
  }

  while (i < 32) {
    GG(a, b, c, d, W[(5 * i + 1) % 16],  5, tab[i]); i++;
    GG(d, a, b, c, W[(5 * i + 1) % 16],  9, tab[i]); i++;
    GG(c, d, a, b, W[(5 * i + 1) % 16], 14, tab[i]); i++;
    GG(b, c, d, a, W[(5 * i + 1) % 16], 20, tab[i]); i++;
  }

  while (i < 48) {
    HH(a, b, c, d, W[(3 * i + 5) % 16],  4, tab[i]); i++;
    HH(d, a, b, c, W[(3 * i + 5) % 16], 11, tab[i]); i++;
    HH(c, d, a, b, W[(3 * i + 5) % 16], 16, tab[i]); i++;
    HH(b, c, d, a, W[(3 * i + 5) % 16], 23, tab[i]); i++;
  }

  while (i < 64) {
    II(a, b, c, d, W[7 * i % 16],  6, tab[i]); i++;
    II(d, a, b, c, W[7 * i % 16], 10, tab[i]); i++;
    II(c, d, a, b, W[7 * i % 16], 15, tab[i]); i++;
    II(b, c, d, a, W[7 * i % 16], 21, tab[i]); i++;
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
}

static void
pad(hash_ctx *ctx)
{
  unsigned r = ctx->len % 64;

  ctx->buf[r++] = 0x80;

  if (r > 56) {
    memset(ctx->buf + r, 0, 64 - r);
    r = 0;
    processblock(ctx, ctx->buf);
  }

  memset(ctx->buf + r, 0, 56 - r);

  ctx->len *= 8;
  ctx->buf[56] = ctx->len;
  ctx->buf[57] = ctx->len >> 8;
  ctx->buf[58] = ctx->len >> 16;
  ctx->buf[59] = ctx->len >> 24;
  ctx->buf[60] = ctx->len >> 32;
  ctx->buf[61] = ctx->len >> 40;
  ctx->buf[62] = ctx->len >> 48;
  ctx->buf[63] = ctx->len >> 56;

  processblock(ctx, ctx->buf);
}

void
md5_init(hash_ctx *ctx)
{
  ctx->len = 0;
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xefcdab89;
  ctx->h[2] = 0x98badcfe;
  ctx->h[3] = 0x10325476;
}

void
md5_update(hash_ctx *ctx, const void *buf, size_t len)
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
md5_finish(hash_ctx *ctx, uint8_t *hash)
{
  int i;

  pad(ctx);
  for (i = 0; i < 4; i++) {
    hash[4 * i + 0] = ctx->h[i];
    hash[4 * i + 1] = ctx->h[i] >> 8;
    hash[4 * i + 2] = ctx->h[i] >> 16;
    hash[4 * i + 3] = ctx->h[i] >> 24;
  }
}

HASH_TYPE_DEFINE(md5, MD5_SIZE_HASH, MD5_SIZE_BLOCK);
