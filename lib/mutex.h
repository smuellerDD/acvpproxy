/*
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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

#ifndef _MUTEX_PTHREAD_H
#define _MUTEX_PTHREAD_H

#include <pthread.h>

#include "logger.h"

/**
 * @brief Reader / Writer mutex based on pthread
 */
typedef pthread_rwlock_t mutex_t;

#define DEFINE_MUTEX_UNLOCKED(name)					\
	mutex_t name = PTHREAD_RWLOCK_INITIALIZER

#define DEFINE_MUTEX_LOCKED(name)					\
	error "DEFINE_MUTEX_LOCKED not implemented"

/**
 * Mutual exclusion lock (covering also the reader lock use case).
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_lock(mutex_t *mutex)
{
	pthread_rwlock_wrlock(mutex);
}

/**
 * Unlock the lock
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_unlock(mutex_t *mutex)
{
	pthread_rwlock_unlock(mutex);
}

/**
 * @brief Initialize a mutex
 * @param mutex [in] Lock variable to initialize.
 * @param locked [in] Specify whether the lock shall already be locked (1)
 *		      or unlocked (0).
 */
static inline void mutex_init(mutex_t *mutex, int locked)
{
	int ret;

	ret = pthread_rwlock_init(mutex, NULL);
	if (ret) {
		logger(LOGGER_ERR, LOGGER_C_THREADING,
		       "Pthread lock initialization failed with %d\n", -ret);
	}

	if (locked)
		mutex_lock(mutex);
}

static inline void mutex_destroy(mutex_t *mutex)
{
	pthread_rwlock_destroy(mutex);
}

/**
 * Mutual exclusion lock when only doing a read (wait when the writer lock
 * is taken but allow parallel reader locks).
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_reader_lock(mutex_t *mutex)
{
	pthread_rwlock_rdlock(mutex);
}

/**
 * Unlock the reader lock
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_reader_unlock(mutex_t *mutex)
{
	pthread_rwlock_unlock(mutex);
}

#endif /* _MUTEX_PTHREAD_H */
