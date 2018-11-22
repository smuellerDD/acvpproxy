/* Threading support - definition
 *
 * Copyright (C) 2018, Stephan Mueller <smueller@chronox.de>
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

#ifndef THREADING_SUPPORT_H
#define THREADING_SUPPORT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Thread groups
 * =============
 *
 * The threading code maintains separate pools of threads for each thread
 * group. Threads belonging to a common purpose should be created within the
 * same thread group. Thread groups are intended to ensure that the threading
 * resources are not exhausted for different purposes.
 *
 * For example, if you have a set of threads which can spawn new threads,
 * you want to ensure that the "mother" threads are in a separate thread
 * group than the "child" threads. This ensures that there is no dead-lock
 * scenario where the "child" threads exhaust all threading resources
 * not allowing a "mother" thread to be created to handle the "children".
 *
 * Special Thread Groups
 * ---------------------
 *
 * Special thread groups ensure that one thread per special thread
 * group is reserved. I.e. for the purpose of the special case, the
 * thread handler will not use such special thread for other purposes.
 *
 * NOTE: When using thread_start for such a special case, make sure to invoke
 *	 this function with the special thread group identifier.
 *
 * These identifiers should not collide with the "regular" group IDs which
 * start at 0.
 *
 * The ACVP_THREAD_MAX_SPECIAL_GROUPS specifies how many special threading
 * groups are available.
 */
#define ACVP_THREAD_TOTP_SERVER_GROUP	((uint32_t) -1)
#define ACVP_THREAD_SIGHANDLER_GROUP	((uint32_t) -2)
#define ACVP_THREAD_MAX_SPECIAL_GROUPS	2

/**
 * @brief - Initializiation of the threading support
 *
 * @param groups [in] Number of groups of threads that are contending and
 *		      yet one thread out of each group must be available.
 *
 * @return: 0 on success, < 0 on error
 */
int thread_init(uint32_t groups);

/**
 * @brief - Wait for currently executing threads and release threading support
 *
 * @param force Shall the threads being attached and waited for (false) or
 *		whether the running processes shall be killed (true)
 * @param system_threads Shall the system threads being terminated (true)
 *			 or not (false).
 *
 * @return All return codes of all thread functions ORed together.
 */
int thread_release(bool force, bool system_threads);

/**
 * @brief - Wait for currently executing threads
 *
 * @return All return codes of all thread functions ORed together.
 */
int thread_wait(void);

/**
 * @brief - Start a function in a separate thread
 *
 * @param start_routine [in] Function that is invoked in thread (the idea is
 *			     that the return code is 0 for success and != 0 for
 *			     error)
 * @param tdata [in] Argument supplied to function
 * @param thread_group [in] Which thread group the thread belongs to.
 * @param ret_ancestor [out] Return code of garbage-collected ancestor. It may
 *			     be NULL if the return code is not of interest.
 *
 * @return 0 on success, < 0 on error
 */
int thread_start(int(*start_routine)(void *), void *tdata,
		 uint32_t thread_group, int *ret_ancestor);

#ifdef __cplusplus
}
#endif

#endif /* THREADING_SUPPORT_H */
