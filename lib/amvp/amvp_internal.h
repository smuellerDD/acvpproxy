/*
 * Copyright (C) 2020 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef AMVP_INTERNAL_H
#define AMVP_INTERNAL_H

#include "acvpproxy.h"
#include "bool.h"
#include "buffer.h"
#include "internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Data store directory for sensitive data including debug logs */
#define AMVP_DS_CREDENTIALDIR "amvp-secure-datastore"
#define AMVP_DS_CREDENTIALDIR_PRODUCTION "amvp-secure-datastore-production"
/* Data store directory for testvectors and other regular data */
#define AMVP_DS_DATADIR "amvp-testvectors"
#define AMVP_DS_DATADIR_PRODUCTION "amvp-testvectors-production"

/* Directory of AMVP configuration information */
#define AMVP_DEF_DIR_CMVP "cmvp"
#define AMVP_DEF_FILE_VAL_INFO "module_validation_definition.json"
#define AMVP_DEF_FILE_REGISTRATION "registration_data.json"

/* File holding the metadata about the test session provided by ACVP server */
#define AMVP_DS_MODULEIDMETA "moduleid_metadata.json"

#ifdef __cplusplus
}
#endif

#endif /* AMVP_INTERNAL_H */
