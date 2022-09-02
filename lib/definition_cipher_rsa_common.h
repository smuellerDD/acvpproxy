/*
 * Copyright (C) 2020 - 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef DEFINITION_CIPHER_RSA_COMMON_H
#define DEFINITION_CIPHER_RSA_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

enum rsa_modulo {
	DEF_ALG_RSA_MODULO_UNDEF,
	DEF_ALG_RSA_MODULO_1024,
	DEF_ALG_RSA_MODULO_1536,
	DEF_ALG_RSA_MODULO_2048,
	DEF_ALG_RSA_MODULO_3072,
	DEF_ALG_RSA_MODULO_4096,
	DEF_ALG_RSA_MODULO_5120,
	DEF_ALG_RSA_MODULO_6144,
	DEF_ALG_RSA_MODULO_7168,
	DEF_ALG_RSA_MODULO_8192,
};

#ifdef __cplusplus
}
#endif

#endif /* DEFINITION_CIPHER_RSA_COMMON_H */
