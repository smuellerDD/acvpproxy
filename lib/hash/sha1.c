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
/* Original code public domain sha1 implementation based on rfc3174 and libtomcrypt */
#include "sha1.h"
#include <string.h>

static uint32_t rol(uint32_t n, int k) { return (n << k) | (n >> (32-k)); }
#define F0(b,c,d) (d ^ (b & (c ^ d)))
#define F1(b,c,d) (b ^ c ^ d)
#define F2(b,c,d) ((b & c) | (d & (b | c)))
#define F3(b,c,d) (b ^ c ^ d)
#define G0(a,b,c,d,e,i) e += rol(a,5)+F0(b,c,d)+W[i]+0x5A827999; b = rol(b,30)
#define G1(a,b,c,d,e,i) e += rol(a,5)+F1(b,c,d)+W[i]+0x6ED9EBA1; b = rol(b,30)
#define G2(a,b,c,d,e,i) e += rol(a,5)+F2(b,c,d)+W[i]+0x8F1BBCDC; b = rol(b,30)
#define G3(a,b,c,d,e,i) e += rol(a,5)+F3(b,c,d)+W[i]+0xCA62C1D6; b = rol(b,30)

static void
processblock(hash_ctx *ctx, const uint8_t *buf)
{
  uint32_t W[80], a, b, c, d, e;
  int i;

  for (i = 0; i < 16; i++) {
    W[i]  = (uint32_t) buf[4 * i + 0] << 24;
    W[i] |= (uint32_t) buf[4 * i + 1] << 16;
    W[i] |= (uint32_t) buf[4 * i + 2] << 8;
    W[i] |= buf[4 * i + 3];
  }

  for (; i < 80; i++)
    W[i] = rol(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);

  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];

  for (i = 0; i < 20;) {
    G0(a, b, c, d, e, i++);
    G0(e, a, b, c, d, i++);
    G0(d, e, a, b, c, i++);
    G0(c, d, e, a, b, i++);
    G0(b, c, d, e, a, i++);
  }

  for (; i < 40;) {
    G1(a, b, c, d, e, i++);
    G1(e, a, b, c, d, i++);
    G1(d, e, a, b, c, i++);
    G1(c, d, e, a, b, i++);
    G1(b, c, d, e, a, i++);
  }

  for (; i < 60;) {
    G2(a, b, c, d, e, i++);
    G2(e, a, b, c, d, i++);
    G2(d, e, a, b, c, i++);
    G2(c, d, e, a, b, i++);
    G2(b, c, d, e, a, i++);
  }

  for (; i < 80;) {
    G3(a, b, c, d, e, i++);
    G3(e, a, b, c, d, i++);
    G3(d, e, a, b, c, i++);
    G3(c, d, e, a, b, i++);
    G3(b, c, d, e, a, i++);
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
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
sha1_init(hash_ctx *ctx)
{
  ctx->len = 0;
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xEFCDAB89;
  ctx->h[2] = 0x98BADCFE;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xC3D2E1F0;
}

void
sha1_update(hash_ctx *ctx, const void *buf, size_t len)
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
sha1_finish(hash_ctx *ctx, uint8_t *hash)
{
  int i;

  pad(ctx);
  for (i = 0; i < 5; i++) {
    hash[4 * i + 0] = ctx->h[i] >> 24;
    hash[4 * i + 1] = ctx->h[i] >> 16;
    hash[4 * i + 2] = ctx->h[i] >> 8;
    hash[4 * i + 3] = ctx->h[i];
  }
}

HASH_TYPE_DEFINE(sha1, SHA1_SIZE_HASH, SHA1_SIZE_BLOCK);
