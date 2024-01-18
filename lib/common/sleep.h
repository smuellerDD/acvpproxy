/*
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef SLEEP_H
#define SLEEP_H

#include "atomic_bool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLEEP_SLEEPTIME_SECONDS 1

/**
 * @brief Sleep the given amount of seconds and periodically check whether
 *	  the sleep should be interrupted.
 *
 * @param sleep_time [in] Time in seconds to sleep
 * @param @interrupted [in] Pointer to boolean that shall cause an interrupt, may be NULL
 *
 * @return 0 on full sleep, -EINTR on interrupt, < 0 on other errors
 */
int sleep_interruptible(const unsigned int sleep_time,
			atomic_bool_t *interrupted);

/**
 * @brief Sleep the given amount of seconds and periodically check whether
 *	  the sleep should be interrupted. Two conditions are checked to interrupt the sleep. If one
 *	  condition is true, the sleep is interrupted.
 *
 * @param sleep_time [in] Time in seconds to sleeep
 * @param @interrupted1 [in] Pointer to boolean that shall cause an interrupt, may be NULL
 * @param @interrupted2 [in] Pointer to boolean that shall cause an interrupt, may be NULL
 *
 * @return 0 on full sleep, -EINTR on interrupt, < 0 on other errors
 */
int sleep_interruptible2(const unsigned int sleep_time,
			 atomic_bool_t *interrupted1,
			 atomic_bool_t *interrupted2);

/**
 * @brief Printing the time duration in a nice user-visible string. The caller
 *	  must provide the start time with start. The function will
 *	  gather the end time stamp and then produces the string.
 *
 * @param start [in] Start time of the measurement
 * @param buf [in/out] Buffer to be filled with the string
 * @param buflen [in] Length of buffer
 *
 * @return 0 on success, < 0 on error
 */
int duration_string(const struct timespec *start, char *buf,
		    const unsigned int buflen);

#ifdef __cplusplus
}
#endif

#endif /* SLEEP_H */
