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

#ifndef _MUTEX_W_H
#define _MUTEX_W_H

#include <sched.h>

#include "atomic_bool.h"

/**
 * @brief Writer mutex with a polling mechanism
 *
 * @param lock Mutex lock (if lock is true, the writer mutex is taken)
 */
typedef struct {
	atomic_bool_t lock;
} mutex_w_t;

#define MUTEX_W_DEFAULT_SLEEP_TIME_NS	(1<<24)		/* 16 milliseconds */
static const struct timespec mutex_w_sleeptime = {
	.tv_sec = 0,
	.tv_nsec = MUTEX_W_DEFAULT_SLEEP_TIME_NS
};

#define __MUTEX_W_INITIALIZER(locked)					\
	{								\
		.lock = ATOMIC_BOOL_INIT(locked),			\
	}

#define DEFINE_MUTEX_W_UNLOCKED(name)					\
	mutex_w_t name = __MUTEX_W_INITIALIZER(false)

#define DEFINE_MUTEX_W_LOCKED(name)					\
	mutex_w_t name = __MUTEX_W_INITIALIZER(true)

/**
 * @brief Initialize a mutex
 * @param mutex [in] Lock variable to initialize.
 * @param locked [in] Specify whether the lock shall already be locked (true)
 *		      or unlocked (false).
 */
static inline void mutex_w_init(mutex_w_t *mutex, bool locked)
{
	atomic_bool_set(locked, &mutex->lock);
}

/**
 * Mutual exclusion lock (covering also the reader lock use case).
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_w_lock(mutex_w_t *mutex)
{
	/* Take the writer lock only if no writer lock is taken. */
	while (!atomic_bool_cmpxchg(&mutex->lock, false, true))
		nanosleep(&mutex_w_sleeptime, NULL);
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
	return atomic_bool_cmpxchg(&mutex->lock, false, true);
}

static inline bool mutex_w_islocked(mutex_w_t *mutex)
{
	return atomic_bool_read(&mutex->lock);
}

/**
 * Unlock the lock
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_w_unlock(mutex_w_t *mutex)
{
	/* Release the writer lock. */
	atomic_bool_cmpxchg(&mutex->lock, true, false);
}

#endif /* _MUTEX_W_H */
