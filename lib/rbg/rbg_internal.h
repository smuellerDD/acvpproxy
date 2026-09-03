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

#ifndef RBG_INTERNAL_H
#define RBG_INTERNAL_H

#include <errno.h>

#include "definition_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* File holding the general entropy source information */
#define RBG_FILE_DEF "definition"

/* Directory containing one sub-directory per conditioning component */
#define RBG_DIR_RBG "rbg"

/* Directory holding documentation */
#define RBG_DIR_DOCUMENTATION "documentation"

#define RBG_CONFIG_FILE_EXTENSION ".json"

/* File holding the metadata about the test session provided by ESVP server */
#define RBG_DS_TESTIDMETA "rbg_metadata.json"

/* File holding the server's information about the RBG session provided by ESVP server */
#define RBG_DS_TESTIDSTATUS "rbg_teststatus.json"

/**
 * Start certification operation
 */
int rbg_certify(struct acvp_testid_ctx *testid_ctx);

int rbg_read_status(struct acvp_testid_ctx *testid_ctx,
		    struct json_object *status);
int rbg_write_status(const struct acvp_testid_ctx *testid_ctx);

#ifdef __cplusplus
}
#endif

#endif /* RBG_INTERNAL_H */
