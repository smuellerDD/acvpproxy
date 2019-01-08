/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
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

#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Maximum number of testID or vsID that can be included into one search
 * request. The search request is compile-time allocated which necessitates
 * the value to be set here.
 */
#define MAX_SUBMIT_ID		64

/*
 * Enable threading support
 */
#define ACVP_USE_PTHREAD

/*
 * Maximum number of concurrent threads supported.
 *
 * This value can be set to any arbitrary number. Depending on the number
 * of threads, the required numbers of thread contexts are statically allocated.
 *
 * There is no other value that needs changing if the number of threads
 * shall be adjusted.
 */
#define THREADING_MAX_THREADS 64

/*
 * Enable the TOTP message queue server
 * NOTE The message queue server requires ACVP_USE_PTHREAD to be set
 */
#define ACVP_TOTP_MQ_SERVER

/*
 * Use the secure_getenv API call instead of getenv which is prone to security
 * issues when not used correctly.
 */
#ifdef __linux__
#define HAVE_SECURE_GETENV
#else
#undef HAVE_SECURE_GETENV
#endif

/************************************************************************
 * Sanity check
 ************************************************************************/
#ifdef ACVP_TOTP_MQ_SERVER
# ifndef ACVP_USE_PTHREAD
#  error "TOTP Message Queue Server requires PTHREAD support"
# endif
#endif

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_H */
