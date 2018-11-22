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

#include <strings.h>

#include "hash.h"

extern hash_spec hash_spec_md5;
extern hash_spec hash_spec_sha1;
extern hash_spec hash_spec_sha224;
extern hash_spec hash_spec_sha256;
extern hash_spec hash_spec_sha384;
extern hash_spec hash_spec_sha512;

static struct {
  const char *name;
  hash_type type;
} types[] = {
  { "md5",    HASH_TYPE_MD5 },
  { "sha1",   HASH_TYPE_SHA1 },
  { "sha224", HASH_TYPE_SHA224 },
  { "sha256", HASH_TYPE_SHA256 },
  { "sha384", HASH_TYPE_SHA384 },
  { "sha512", HASH_TYPE_SHA512 },
  { NULL,     HASH_TYPE_UNKNOWN }
};

static hash_spec *specs[] = {
  &hash_spec_md5,
  &hash_spec_sha1,
  &hash_spec_sha224,
  &hash_spec_sha256,
  &hash_spec_sha384,
  &hash_spec_sha512,
};

static char
tohex(uint8_t b)
{
  b &= 0x0f;

  if (b < 10)
    return '0' + b;

  return 'a' + b - 10;
}

hash_type
hash_type_find(const char *name)
{
  return hash_type_findn(name, 0);
}

hash_type
hash_type_findn(const char *name, size_t size)
{
  for (size_t i = 0; types[i].name; i++) {
    if (strncasecmp(types[i].name, name, size) == 0)
      return types[i].type;
  }

  return HASH_TYPE_UNKNOWN;
}

const char *
hash_type_name(hash_type type)
{
  for (size_t i = 0; types[i].name; i++) {
    if (types[i].type == type)
      return types[i].name;
  }

  return NULL;
}
              
const hash_spec *
hash_spec_get(hash_type type)
{
  if (type == HASH_TYPE_UNKNOWN || type > sizeof(specs) / sizeof(*specs))
    return NULL;

  return specs[type - 1];
}

void
hash_to_hex(const uint8_t *hash, size_t hashsize, char *hex)
{
  for (size_t i = 0; i < hashsize; i++) {
    hex[i * 2 + 0] = tohex(hash[i] >> 4);
    hex[i * 2 + 1] = tohex(hash[i]);
  }
}
