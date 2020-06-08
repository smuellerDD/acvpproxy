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

#ifndef ACVP_ERROR_HANDLER_H
#define ACVP_ERROR_HANDLER_H

#include <buffer.h>

#ifdef __cplusplus
extern "C"
{
#endif

enum acvp_error_code {
	ACVP_ERR_NO_ERR = 0,
	ACVP_ERR_RESPONSE_RECEIVED_VERDICT_PENDING,
};

/**
 * @brief Convert an ACVP Error code into an internal representation
 *
 * @param response_buf [in] Buffer with the JSON response data from the server
 * @param code [out] Error code that was identified from the data
 *
 * @return 0 on successful conversion, < 0 on error
 */
int acvp_error_convert(const struct acvp_buf *response_buf,
		       enum acvp_error_code *code);

#ifdef __cplusplus
}
#endif

#endif /* ACVP_ERROR_HANDLER_H */
