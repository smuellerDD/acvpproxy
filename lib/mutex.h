/*
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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

#ifndef _MUTEX_H
#define _MUTEX_H

#include <time.h>

#include "atomic.h"

/**
 * @brief Reader / Writer mutex
 *
 * @param lock Mutex lock (if lock is -1, the writer mutex is taken)
 * @param lock_lock Lock the write operation of the mutex
 * @param writer_pending If a writer lock is requested, this value is > 0.
 *			 When this value is > 0, a reader lock will not be
 *			 granted any more and it waits until the writer lock
 *			 is cleared.
 * @param sleeptime Sleep time of the reader to acquire the lock
 */
typedef struct {
	atomic_t lock;
	atomic_t lock_lock;
	atomic_t writer_pending;
	struct timespec sleeptime;
} mutex_t;

#define MUTEX_DEFAULT_SLEEP_TIME_NS	(1<<24)		/* 16 milliseconds */

#define __MUTEX_INITIALIZER(locked)					\
	{								\
		.lock = ATOMIC_INIT(locked),				\
		.lock_lock = ATOMIC_INIT(locked),			\
		.writer_pending = ATOMIC_INIT(0),			\
		.sleeptime.tv_sec = 0,					\
		.sleeptime.tv_nsec = MUTEX_DEFAULT_SLEEP_TIME_NS 	\
	}

#define DEFINE_MUTEX_UNLOCKED(name)					\
	mutex_t name = __MUTEX_INITIALIZER(0)

#define DEFINE_MUTEX_LOCKED(name)					\
	mutex_t name = __MUTEX_INITIALIZER(-1)

/**
 * @brief Initialize a mutex
 * @param mutex [in] Lock variable to initialize.
 * @param locked [in] Specify whether the lock shall already be locked (1)
 *		      or unlocked (0).
 * @param sleep_ns [in] Specify the sleep time in ns. If zero, the default
 *			sleep time is used.
 */
static inline void mutex_init(mutex_t *mutex, int locked, long sleep_ns)
{
	if (locked)
		atomic_set(-1, &mutex->lock);
	else
		atomic_set(0, &mutex->lock);

	atomic_set(0, &mutex->lock_lock);
	atomic_set(0, &mutex->writer_pending);

	mutex->sleeptime.tv_sec = 0;
	if (sleep_ns > 0)
		mutex->sleeptime.tv_nsec = sleep_ns;
	else
		mutex->sleeptime.tv_nsec = MUTEX_DEFAULT_SLEEP_TIME_NS;
}

/**
 * Mutual exclusion lock (covering also the reader lock use case).
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_lock(mutex_t *mutex)
{
	atomic_inc(&mutex->writer_pending);

	while (1) {
		/* Lock the potential non-atomic op of setting the lock. */
		while (!atomic_cmpxchg(&mutex->lock_lock, 0, -1)) { }

		/* Take the writer lock only if no writer lock is taken. */
		if (atomic_cmpxchg(&mutex->lock, 0, -1)) {
			/* Unlock the lock setting operation. */
			atomic_cmpxchg(&mutex->lock_lock, -1, 0);
			break;
		}

		/* Unlock the lock setting operation. */
		atomic_cmpxchg(&mutex->lock_lock, -1, 0);
		nanosleep(&mutex->sleeptime, NULL);
	}

	atomic_dec(&mutex->writer_pending);
}

/**
 * Unlock the lock
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_unlock(mutex_t *mutex)
{
	/* Lock the potential non-atomic operation of setting the lock. */
	while (!atomic_cmpxchg(&mutex->lock_lock, 0, -1)) { }

	/* Release the writer lock. */
	atomic_cmpxchg(&mutex->lock, -1, 0);

	/* Unlock the lock setting operation. */
	atomic_cmpxchg(&mutex->lock_lock, -1, 0);
}

/**
 * Mutual exclusion lock when only doing a read (wait when the writer lock
 * is taken but allow parallel reader locks).
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_reader_lock(mutex_t *mutex)
{
	/* If there is a writer pending, it takes precedence and reader waits */
	while (!atomic_cmpxchg(&mutex->writer_pending, 0, 0))
		nanosleep(&mutex->sleeptime, NULL);

	while (1) {
		/* Lock the potential non-atomic op of setting the lock. */
		while (!atomic_cmpxchg(&mutex->lock_lock, 0, -1)) { }

		/*
		 * Take the reader lock only if no writer lock is taken.
		 *
		 * This is the place why we need mutex->lock_lock: neither
		 * atomic_cmpxchg nor atomic_add_and_test provide an atomic
		 * primitive to set the lock with a check.
		 */
		if (atomic_read(&mutex->lock) != -1) {
			atomic_inc(&mutex->lock);

			/* Unlock the lock setting operation. */
			atomic_cmpxchg(&mutex->lock_lock, -1, 0);
			break;
		}

		/* Unlock the lock setting operation. */
		atomic_cmpxchg(&mutex->lock_lock, -1, 0);
		nanosleep(&mutex->sleeptime, NULL);
	}
}

/**
 * Unlock the reader lock
 * @param lock [in] lock variable to lock
 */
static inline void mutex_reader_unlock(mutex_t *mutex)
{
	/* Lock the potential non-atomic operation of setting the lock. */
	while (!atomic_cmpxchg(&mutex->lock_lock, 0, -1)) { }

	/* Release the reader lock */
	atomic_dec(&mutex->lock);

	/* Unlock the lock setting operation. */
	atomic_cmpxchg(&mutex->lock_lock, -1, 0);
}

#endif /* _MUTEX_H */
