/*
 * Copyright (C) 2018 - 2019, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#ifndef _MUTEX_W_PTHREAD_H
#define _MUTEX_W_PTHREAD_H

#include <pthread.h>

#include "logger.h"

/**
 * @brief Reader / Writer mutex based on pthread
 */
typedef pthread_mutex_t mutex_w_t;

#define DEFINE_MUTEX_W_UNLOCKED(name)					\
	mutex_w_t name = PTHREAD_MUTEX_INITIALIZER

#define DEFINE_MUTEX_W_LOCKED(name)					\
	error "DEFINE_MUTEX_LOCKED not implemented"

/**
 * Mutual exclusion lock (covering also the reader lock use case).
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_w_lock(mutex_w_t *mutex)
{
	pthread_mutex_lock(mutex);
}

/**
 * Unlock the lock
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_w_unlock(mutex_w_t *mutex)
{
	pthread_mutex_unlock(mutex);
}

/**
 * @brief Initialize a mutex
 * @param mutex [in] Lock variable to initialize.
 * @param locked [in] Specify whether the lock shall already be locked (1)
 *		      or unlocked (0).
 */
static inline void mutex_w_init(mutex_w_t *mutex, int locked)
{
	int ret;

	ret = pthread_mutex_init(mutex, NULL);
	if (ret) {
		logger(LOGGER_ERR, LOGGER_C_THREADING,
		       "Pthread lock initialization failed with %d\n", -ret);
	}

	if (locked)
		pthread_mutex_lock(mutex);
}

static inline void mutex_w_destroy(mutex_w_t *mutex)
{
	pthread_mutex_destroy(mutex);
}

/**
 * Mutual exclusion lock: Attempt to take the lock. The function will never
 * block but return whether the lock was successfully taken or not.
 *
 * @param mutex [in] lock variable to lock
 * @return true if lock was taken, false if lock was not taken
 */
static inline bool mutex_w_trylock(mutex_w_t *mutex)
{
	if (pthread_mutex_trylock(mutex))
		return false;
	return true;
}

#endif /* _MUTEX_W_PTHREAD_H */
