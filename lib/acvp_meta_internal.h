/*
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

#ifndef ACVP_META_H
#define ACVP_META_H

#include "internal.h"

#ifdef __cplusplus
extern "C"
{
#endif

/******************************************************************************
 * ACVP meta data handler internal functions
 ******************************************************************************/

/**
 * @brief Validate and potentially register vendor definition
 */
int acvp_vendor_handle(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Validate and potentially register person / contact definition
 */
int acvp_person_handle(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Validate and potentially register operational environment definition
 */
int acvp_oe_handle(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Validate and potentially register module definition
 */
int acvp_module_handle(const struct acvp_testid_ctx *testid_ctx);

/**
 * @brief Fetch open registration requests if there are some present
 */
int acvp_vendor_handle_open_requests(const struct acvp_testid_ctx *testid_ctx);
int acvp_person_handle_open_requests(const struct acvp_testid_ctx *testid_ctx);
int acvp_oe_handle_open_requests(const struct acvp_testid_ctx *testid_ctx);
int acvp_module_handle_open_requests(const struct acvp_testid_ctx *testid_ctx);

#ifdef __cplusplus
}
#endif

#endif /* ACVP_META_H */
