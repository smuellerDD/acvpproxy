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
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once
#include <stddef.h>
#include <stdint.h>

#define HASH_TYPE_DEFINE(name, hsize, bsize) \
  hash_spec hash_spec_ ## name = { \
    .ctx = sizeof(hash_ctx), \
    .hash = hsize, \
    .block = bsize, \
    .init = name ## _init, \
    .update = name ## _update, \
    .finish = name ## _finish, \
  }

typedef enum {
  HASH_TYPE_UNKNOWN,
  HASH_TYPE_MD5,
  HASH_TYPE_SHA1,
  HASH_TYPE_SHA224,
  HASH_TYPE_SHA256,
  HASH_TYPE_SHA384,
  HASH_TYPE_SHA512,
} hash_type;

typedef struct hash_ctx hash_ctx;

typedef struct hash_spec {
  size_t ctx;
  size_t hash;
  size_t block;
  void (*init)(hash_ctx *ctx);
  void (*update)(hash_ctx *ctx, const void *buf, size_t len);
  void (*finish)(hash_ctx *ctx, uint8_t *hash);
} hash_spec;

hash_type
hash_type_find(const char *name);

hash_type
hash_type_findn(const char *name, size_t size);

const char *
hash_type_name(hash_type type);

const hash_spec *
hash_spec_get(hash_type type);

void
hash_to_hex(const uint8_t *hash, size_t hashsize, char *hex);
