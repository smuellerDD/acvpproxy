/* Threading support - implementation
 *
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

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "atomic_bool.h"
#include "bool.h"
#include "config.h"
#include "logger.h"
#include "mutex_w.h"
#include "ret_checkers.h"

#include "threading_support.h"

#ifdef ACVP_USE_PTHREAD

/**
 * Threading Support
 * =================
 *
 * Threading support is provided by maintaining a pool of threads which
 * are spawned when they are needed. Once the thread completes its first job
 * it remains idle but alive and waits for the next job. The code first
 * tries to reuse existing idle threads before spawning new threads.
 *
 * It is permissible to spawn new threads from different mother threads. When
 * calling thread_wait, only the threads from the caller are waited for.
 */

/*
 * Structure for one thread
 */
struct thread_ctx {
	pthread_t thread_id;		/* Thread ID from pthread_create */
	pthread_t parent;		/* Parent thread ID */
	unsigned int thread_num;	/* Current slot number */
	int ret_ancestor;		/* Return code of ancestor code */

	int (*start_routine)(void *);	/* Thread code to be executed */
	void *data;			/* Parameters used by the thread code */

	atomic_bool_t thread_pending;	/* Is thread associated with structure? */
	mutex_w_t inuse;		/* Is thread data structure used? */
	atomic_bool_t shutdown;		/* Shall the thread be shut down? */
	bool scheduled;			/* Is/was a job executed and return code
					 * is ready for pickup? */
};

/*
 * Total number of all threads, including slaves and system threads.
 */
#define THREADING_REALLY_ALL_THREADS	(THREADING_MAX_THREADS +	\
					 ACVP_THREAD_MAX_SPECIAL_GROUPS)

/*
 * Array holding the thread state for all slaves and system threads.
 */
static struct thread_ctx threads[THREADING_REALLY_ALL_THREADS];
static uint32_t threads_groups = 0;
static uint32_t threads_per_threadgroup = 1;

static pthread_attr_t pthread_attr;

/*
 * Indicator to prevent spawning of new threads while the cleanup / garbage
 * collector functions execute.
 */
static atomic_bool_t threads_in_cancel = ATOMIC_BOOL_INIT(false);

/*
 * Lock whether the cleanup / garbage collector for threads executes. As we
 * have two cleanup functions, we must ensure that they do not execute at the
 * same time.
 */
static DEFINE_MUTEX_W_UNLOCKED(threads_cleanup);

static inline unsigned int thread_get_special_slot(unsigned int thread_group)
{
	if (thread_group <= THREADING_MAX_THREADS)
		return 0;

	/* Special groups are defined as (uint32_t)-1 and lower */
	return (THREADING_MAX_THREADS + (UINT_MAX - thread_group));
}

static inline bool thread_is_special(struct thread_ctx *tctx)
{
	return (tctx->thread_num >= THREADING_MAX_THREADS) ? true : false;
}

int thread_init(uint32_t groups)
{
	static uint32_t thread_initialized = 0;
	unsigned int i;
	int ret;

	if (groups > (THREADING_MAX_THREADS)) {
		logger(LOGGER_ERR, LOGGER_C_THREADING,
		       "Number of threads (%lu) is less than the number of requested thread groups (%u)\n",
		       THREADING_MAX_THREADS, groups);
		return -EINVAL;
	}

	if (groups == 0)
		groups = 1;

	if (thread_initialized)
		goto out;
	thread_initialized = 1;

	CKINT(pthread_attr_init(&pthread_attr));
	memset(threads, 0, sizeof(threads));

	for (i = 0; i < THREADING_REALLY_ALL_THREADS; i++) {
		mutex_w_init(&threads[i].inuse, false);
		atomic_bool_set_false(&threads[i].shutdown);
	}

	threads_groups = groups;
	threads_per_threadgroup = THREADING_MAX_THREADS / threads_groups;

	logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
	       "Initialized threading support for %u threads\n",
	       THREADING_MAX_THREADS);
	if (threads_per_threadgroup * threads_groups < THREADING_MAX_THREADS) {
		logger(LOGGER_WARN, LOGGER_C_THREADING,
		       "%u thread slots will never be used\n",
		       THREADING_MAX_THREADS - (threads_per_threadgroup *
						threads_groups));
	}

out:
	return 0;
}

static inline void thread_block(void)
{
	const struct timespec sleeptime = {
		.tv_sec = 0,
		.tv_nsec = 1<<27
	};

	nanosleep(&sleeptime, NULL);
}

static inline bool thread_dirty(unsigned int slot)
{
	return (atomic_bool_read(&threads[slot].thread_pending));
}

/* Thread structure cleanup after execution when thread is kept alive. */
static inline void thread_cleanup(struct thread_ctx *tctx)
{
	tctx->data = NULL;
	tctx->start_routine = NULL;

	/* Return values of special threads is irrelevant */
	if (thread_is_special(tctx))
		tctx->scheduled = false;
}

/* Thread structure cleanup when thread is terminated. */
static inline void thread_cleanup_full(struct thread_ctx *tctx)
{
	thread_cleanup(tctx);
	tctx->thread_num = 0;
	atomic_bool_set_false(&tctx->thread_pending);
	tctx->scheduled = false;
	tctx->ret_ancestor = 0;
	mutex_w_destroy(&tctx->inuse);
}

/* Worker loop of a thread */
static void *thread_worker(void *arg)
{
	sigset_t block, old;
	struct thread_ctx *tctx = (struct thread_ctx *)arg;
	int ret;

	/* Block all signals from being processed by thread */
	sigfillset(&block);
	ret = -pthread_sigmask(SIG_BLOCK, &block, &old);
	if (ret)
		return NULL;

	while (1) {
		mutex_w_lock(&tctx->inuse);

		if (atomic_bool_read(&tctx->shutdown)) {
			/* Request for termination */
			mutex_w_unlock(&tctx->inuse);
			break;
		} else if (tctx->start_routine) {
			/* Work to do, execute */
			tctx->ret_ancestor = tctx->start_routine(tctx->data);
			thread_cleanup(tctx);
			logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
			       "Thread %u completed\n",
			       tctx->thread_num);
			mutex_w_unlock(&tctx->inuse);
		} else {
			/* Idle */
			mutex_w_unlock(&tctx->inuse);
			thread_block();
		}
	}

	return NULL;
}

/* Spawn a thread */
static int thread_create(struct thread_ctx *tctx, unsigned int slot)
{
	int ret;

	tctx->thread_num = slot;
	tctx->data = NULL;
	atomic_bool_set_true(&tctx->thread_pending);

	ret = -pthread_create(&tctx->thread_id, &pthread_attr, &thread_worker,
			      tctx);
	if (ret)
		goto err;

	return 0;

err:
	thread_cleanup_full(tctx);
	return ret;
}

/* Find free pthread slot and schedule the job */
static int thread_schedule(int(*start_routine)(void *), void *tdata,
			   uint32_t thread_group, int *ret_ancestor)
{
	pthread_t self = pthread_self();
	unsigned int i, upper;
	unsigned int special_slot = thread_get_special_slot(thread_group);

	if (threads_groups < thread_group && !special_slot) {
		logger(LOGGER_ERR, LOGGER_C_THREADING,
		       "undefined thread group requested (%u, max thread group is %u)\n",
		       thread_group, threads_groups);
		return -EINVAL;
	}

	/* Get the range of slots of the thread_group */
	if (special_slot) {
		i = special_slot;
		upper = special_slot + 1;
	} else {
		i = thread_group * threads_per_threadgroup;
		upper = (thread_group + 1) * threads_per_threadgroup;
	}

	for (; i < upper; i++) {
		if (mutex_w_trylock(&threads[i].inuse)) {
			/* The thread is currently executing a body of code */
			if (threads[i].start_routine ||
			    atomic_bool_read(&threads[i].shutdown)) {
				mutex_w_unlock(&threads[i].inuse);
				continue;
			}

			/*
			 * Thread is not being picked up by thread_wait of the
			 * mother thread, skip.
			 */
			if (threads[i].scheduled &&
			    !pthread_equal(threads[i].parent, self)) {
				mutex_w_unlock(&threads[i].inuse);
				continue;
			}

			/*
			 * Create thread as we have a clean slot and all
			 * existing threads are busy.
			 */
			if (!thread_dirty(i)) {
				int ret = thread_create(&threads[i], i);

				if (ret)
					return ret;

				logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
				       "Thread %u for thread group %u allocated\n",
				       i, thread_group);
			}

			/* Catch the return code of the ancestor thread */
			if (ret_ancestor)
				*ret_ancestor = threads[i].ret_ancestor;

			/*
			 * Use the thread from the thread pool and schedule
			 * job.
			 */
			logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
			       "Thread %u for thread group %u assigned\n",
			       i, thread_group);
			threads[i].data = tdata;
			threads[i].start_routine = start_routine;
			threads[i].parent = pthread_self();
			threads[i].scheduled = true;
			mutex_w_unlock(&threads[i].inuse);
			return 0;
		}
	}

	return -EAGAIN;
}

/*
 * Wait for all threads in spawned by calling thread and fetch the return code.
 */
int thread_wait(void)
{
	unsigned int i;
	pthread_t self = pthread_self();
	int ret = 0;
	bool wait = true;

	while (wait) {
		wait = false;

		/* Only wait for our children */
		for (i = 0; i < THREADING_MAX_THREADS; i++) {

			/* Thread is not initialized, skip */
			if (!thread_dirty(i))
				continue;

			if (atomic_bool_read(&threads[i].shutdown))
				continue;

			/* Thread is not one of our children, skip */
			if (!pthread_equal(threads[i].parent, self))
				continue;

			/* If the thread executes a job, skip but wait wait. */
			if (!mutex_w_trylock(&threads[i].inuse)) {
				wait = true;
				continue;
			}

			/*
			 * If there is a start routine, a job is pending and we
			 * wait for it to finish.
			 */
			if (threads[i].start_routine) {
				wait = true;
			} else {
				/* Collect return code of our threads */
				ret |= threads[i].ret_ancestor;
				threads[i].scheduled = false;
			}

			mutex_w_unlock(&threads[i].inuse);
		}

		if (wait)
			thread_block();
	}

	return ret;
}

/* Wait for all threads */
static int thread_wait_all(bool system_threads)
{
	unsigned int i, upper = system_threads ? THREADING_REALLY_ALL_THREADS :
						 THREADING_MAX_THREADS;
	int ret = 0;

	mutex_w_lock(&threads_cleanup);

	/* Ensure that no new thread is spawned. */
	for (i = 0; i < upper; i++)
		atomic_bool_set_true(&threads[i].shutdown);

	/* Wait for all worker threads. */
	for (i = 0; i < upper; i++) {
		if (thread_dirty(i)) {
			pthread_join(threads[i].thread_id, NULL);
			ret |= threads[i].ret_ancestor;
			thread_cleanup_full(&threads[i]);
			logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
			       "Thread %u terminated\n", i);
		}
	}

	/* Allow new threads being spawned */
	for (i = 0; i < upper; i++)
		atomic_bool_set_false(&threads[i].shutdown);

	mutex_w_unlock(&threads_cleanup);

	return ret;
}

/* Kill all threads */
static void thread_cancel(bool system_threads)
{
	unsigned int i, upper = system_threads ? THREADING_REALLY_ALL_THREADS :
						 THREADING_MAX_THREADS;

	atomic_bool_set_true(&threads_in_cancel);
	mutex_w_lock(&threads_cleanup);
	/* Ensure that no new thread is spawned. */
	for (i = 0; i < upper; i++) {
		atomic_bool_set_true(&threads[i].shutdown);
		threads[i].start_routine = NULL;
	}

	/* Kill all worker threads. */
	for (i = 0; i < upper; i++) {
		if (thread_dirty(i)) {
			pthread_cancel(threads[i].thread_id);
			pthread_join(threads[i].thread_id, NULL);
			thread_cleanup_full(&threads[i]);
			logger(LOGGER_VERBOSE, LOGGER_C_THREADING,
			       "Thread %u killed\n", i);
		}
	}

	/*
	 * Do not set threads[i].shutdown to false any more as no new
	 * thread shall be spawned. We are in the process of dying.
	 */

	mutex_w_unlock(&threads_cleanup);
}

int thread_start(int(*start_routine)(void *), void *tdata,
		 uint32_t thread_group, int *ret_ancestor)
{
	int ret;

	while (1) {
		ret = thread_schedule(start_routine, tdata, thread_group,
				      ret_ancestor);
		if (atomic_bool_read(&threads_in_cancel))
			return -ESHUTDOWN;
		else if (ret == -EAGAIN)
			thread_block();
		else
			return ret;
	}

	return 0;
}

int thread_release(bool force, bool system_threads)
{
	int ret = 0;

	if (force)
		thread_cancel(system_threads);
	else
		ret = thread_wait_all(system_threads);

	/* do not handle return code as we are terminating anyway */
	pthread_attr_destroy(&pthread_attr);
	return ret;
}

#else

int thread_init(uint32_t groups) { (void) groups; return 0; }
int thread_release(bool force, bool system_threads)
{
	(void)force;
	(void)system_threads;
	return 0;

}
int thread_wait(void) { return 0; }
int thread_start(int(*start_routine)(void *), void *tdata,
		 uint32_t thread_group, int *ret_ancestor)
{
	(void)start_routine;
	(void)tdata;
	(void)thread_group;
	(void)ret_ancestor;
	return 0;
}

#endif /* ACVP_USE_PTHREAD */
