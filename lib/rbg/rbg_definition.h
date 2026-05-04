/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef RBG_DEFINITION_H
#define RBG_DEFINITION_H

#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct rbg_def {
	//TODO due to es_auth, this structure cannot be constified any more
	// which implies that all operations must be single-threaded
	// fix: create some
	// struct rbg_es_def_instance {const struct rbg_es_def' struct acvp_auth_ctx *es_auth;}
	struct acvp_auth_ctx *rbg_auth;

	bool esv_submission;

#define RBG_MAX_DEFINITIONS 10
	struct json_object *rbg_definitions[RBG_MAX_DEFINITIONS];
	unsigned int num_rbg_definitions;
};

void rbg_def_free(struct rbg_def *es);
int rbg_def_config(const char *directory, struct rbg_def **es);

#ifdef __cplusplus
}
#endif

#endif /* RBG_DEFINITION_H */
