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
/* Original code public domain sha512 implementation based on fips180-3 */
/* >=2^64 bits messages are not supported (about 2000 peta bytes) */
#include "sha512.h"
#include <string.h>

static uint64_t ror(uint64_t n, int k) { return (n >> k) | (n << (64-k)); }
#define Ch(x,y,z)  (z ^ (x & (y ^ z)))
#define Maj(x,y,z) ((x & y) | (z & (x | y)))
#define S0(x)      (ror(x,28) ^ ror(x,34) ^ ror(x,39))
#define S1(x)      (ror(x,14) ^ ror(x,18) ^ ror(x,41))
#define R0(x)      (ror(x,1) ^ ror(x,8) ^ (x>>7))
#define R1(x)      (ror(x,19) ^ ror(x,61) ^ (x>>6))

static const uint64_t K[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
  0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
  0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
  0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
  0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
  0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
  0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
  0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
  0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
  0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
  0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
  0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
  0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
  0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
  0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
  0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
  0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

static void
processblock(hash_ctx *ctx, const uint8_t *buf)
{
  uint64_t W[80], t1, t2, a, b, c, d, e, f, g, h;
  int i;

  for (i = 0; i < 16; i++) {
    W[i]  = (uint64_t) buf[8 * i + 0] << 56;
    W[i] |= (uint64_t) buf[8 * i + 1] << 48;
    W[i] |= (uint64_t) buf[8 * i + 2] << 40;
    W[i] |= (uint64_t) buf[8 * i + 3] << 32;
    W[i] |= (uint64_t) buf[8 * i + 4] << 24;
    W[i] |= (uint64_t) buf[8 * i + 5] << 16;
    W[i] |= (uint64_t) buf[8 * i + 6] << 8;
    W[i] |= buf[8 * i + 7];
  }

  for (; i < 80; i++)
    W[i] = R1(W[i-2]) + W[i - 7] + R0(W[i - 15]) + W[i - 16];

  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];
  f = ctx->h[5];
  g = ctx->h[6];
  h = ctx->h[7];

  for (i = 0; i < 80; i++) {
    t1 = h + S1(e) + Ch(e, f, g) + K[i] + W[i];
    t2 = S0(a) + Maj(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
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
  unsigned r = ctx->len % 128;

  ctx->buf[r++] = 0x80;
  if (r > 112) {
    memset(ctx->buf + r, 0, 128 - r);
    r = 0;
    processblock(ctx, ctx->buf);
  }

  memset(ctx->buf + r, 0, 120 - r);

  ctx->len *= 8;
  ctx->buf[120] = ctx->len >> 56;
  ctx->buf[121] = ctx->len >> 48;
  ctx->buf[122] = ctx->len >> 40;
  ctx->buf[123] = ctx->len >> 32;
  ctx->buf[124] = ctx->len >> 24;
  ctx->buf[125] = ctx->len >> 16;
  ctx->buf[126] = ctx->len >> 8;
  ctx->buf[127] = ctx->len;

  processblock(ctx, ctx->buf);
}

void
sha512_init(hash_ctx *ctx)
{
  ctx->len = 0;
  ctx->h[0] = 0x6a09e667f3bcc908ULL;
  ctx->h[1] = 0xbb67ae8584caa73bULL;
  ctx->h[2] = 0x3c6ef372fe94f82bULL;
  ctx->h[3] = 0xa54ff53a5f1d36f1ULL;
  ctx->h[4] = 0x510e527fade682d1ULL;
  ctx->h[5] = 0x9b05688c2b3e6c1fULL;
  ctx->h[6] = 0x1f83d9abfb41bd6bULL;
  ctx->h[7] = 0x5be0cd19137e2179ULL;
}

void
sha512_update(hash_ctx *ctx, const void *buf, size_t len)
{
  const uint8_t *p = buf;
  unsigned r = ctx->len % 128;

  ctx->len += len;
  if (r) {
    if (len < 128 - r) {
      memcpy(ctx->buf + r, p, len);
      return;
    }

    memcpy(ctx->buf + r, p, 128 - r);

    len -= 128 - r;
    p += 128 - r;

    processblock(ctx, ctx->buf);
  }

  for (; len >= 128; len -= 128, p += 128)
    processblock(ctx, p);

  memcpy(ctx->buf, p, len);
}

void
sha512_finish(hash_ctx *ctx, uint8_t *hash)
{
  int i;

  pad(ctx);
  for (i = 0; i < 8; i++) {
    hash[8 * i + 0] = ctx->h[i] >> 56;
    hash[8 * i + 1] = ctx->h[i] >> 48;
    hash[8 * i + 2] = ctx->h[i] >> 40;
    hash[8 * i + 3] = ctx->h[i] >> 32;
    hash[8 * i + 4] = ctx->h[i] >> 24;
    hash[8 * i + 5] = ctx->h[i] >> 16;
    hash[8 * i + 6] = ctx->h[i] >> 8;
    hash[8 * i + 7] = ctx->h[i];
  }
}

HASH_TYPE_DEFINE(sha512, SHA512_SIZE_HASH, SHA512_SIZE_BLOCK);
