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

#define AMVP_DEF_FILE_TE "te.json"

/* Security Policy section files found in AMVP configuration directory */
#define AMVP_DEF_SP_GENERAL "sp_general.json"
#define AMVP_DEF_SP_CRYPT_MOD_INTERFACES "sp_cryptographic_module_interfaces.json"
#define AMVP_DEF_SP_CRYPT_MOD_SPEC "sp_cryptographic_module_specification.json"
#define AMVP_DEF_SP_LIFECYCLE "sp_lifecycle_assurance.json"
#define AMVP_DEF_SP_OE "sp_operational_environment.json"
#define AMVP_DEF_SP_MITIGATION_OTHER_ATTACKS "sp_mitigation_of_other_attacks.json"
#define AMVP_DEF_SP_NON_INVASIVE_SEC "sp_non_invasive_security.json"
#define AMVP_DEF_SP_PHYS_SEC "sp_physical_security.json"
#define AMVP_DEF_SP_ROLES_SERVICES "sp_roles_services_authentication.json"
#define AMVP_DEF_SP_SELF_TESTS "sp_self_tests.json"
#define AMVP_DEF_SSP_MGMT "sp_sensitive_security_parameter_management.json"
#define AMVP_DEF_SW_FW_SEC "sp_software_firmware_security.json"

/* File holding the metadata about the test session provided by ACVP server */
#define AMVP_DS_MODULEIDMETA "moduleid_metadata.json"

#define AMVP_DS_SP_FILENAME "_140sp.pdf"

int amvp_alloc_state(struct acvp_testid_ctx *testid_ctx);
void amvp_release_state(struct acvp_testid_ctx *testid_ctx);
int amvp_read_status(struct acvp_testid_ctx *testid_ctx,
		     struct json_object *status);
int amvp_write_status(const struct acvp_testid_ctx *testid_ctx);

int amvp_te_get(const struct acvp_vsid_ctx *certreq_ctx);
int amvp_te_upload_evidence(const struct acvp_vsid_ctx *certreq_ctx,
			    const struct acvp_buf *buf);
int amvp_te_status(const struct acvp_vsid_ctx *certreq_ctx,
		   struct json_object *data);

int amvp_sp_upload_evidence(const struct acvp_vsid_ctx *certreq_ctx);
int amvp_sp_status(const struct acvp_vsid_ctx *certreq_ctx,
		   struct json_object *data);
int amvp_sp_get_pdf(const struct acvp_vsid_ctx *certreq_ctx);

int amvp_module_register_op(struct acvp_testid_ctx *module_ctx);

int amvp_certrequest_register(struct acvp_testid_ctx *module_ctx);

#ifdef __cplusplus
}
#endif

#endif /* AMVP_INTERNAL_H */
