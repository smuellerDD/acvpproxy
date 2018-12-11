/* ACVP signal handler
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

#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "definition.h"
#include "internal.h"
#include "logger.h"
#include "mutex_w.h"
#include "totp.h"
#include "request_helper.h"
#include "sleep.h"
#include "threading_support.h"

/**
 * Signal Handler
 * ==============
 *
 * In case of a threaded application, the signal handler is placed into its
 * own signal handler thread where all other threads block all signals.
 *
 * The signal handler thread cleans up the entire ACVP system except the threads
 * belonging to special "system" groups (like the signal handler thread). It
 * also implements the graceful shutdown of the TOTP MQ server.
 *
 * The master thread also has a signal handler which waits for the "system"
 * group threads to finish to clean up this thread. The master thread is
 * not implementing any other cleanup operation.
 *
 * The signal handler thread uses the sigwait system call. If this is
 * not implemented by the OS, the entire signal handling will be left
 * in the master thread and no signal handler thread is created. This, however,
 * may cause a deadlock in some edge conditions where the entire process
 * can only be killed. This deadlock is due to the following: when the
 * master thread receives a signal, all children are not scheduled any more
 * (at least on Linux that is). However, the TOTP MQ server thread usually
 * waits in the msgrcv system call for new messages blocked by the operating
 * system kernel. When it is not scheduled any more, it cannot be terminated
 * with pthread_cancel as it waits in the kernel. Furthermore, the TOTP MQ
 * server will not process any message which could lead to a shutdown of the
 * MQ server since msgrcv will not unblock to deliver it. Also, msgrcv does
 * not unblock when the MQ server message queue is removed as the MQ server
 * thread is not scheduled by the operating system. Thus, there is no way to
 * unblock the msgrcv other than a SIGKILL to the entire ACVP Proxy process.
 *
 * NOTE: If you kill the process, the server message queue may not be
 * cleaned up properly which could prevent the MQ server from being spawned
 * next time. To fix that, either (i) start the ACVP Proxy once without much
 * work (e.g. acvp-proxy --request --dump-register) but where it attempts to
 * start the MQ server, (ii) use the operating system means to clean up
 * the message queue, or (iii) reboot the OS.
 */

/*
 * Linked list holding all testID structures currently executing for a
 * potential cleanup in case we are interrupted.
 */
static struct acvp_testid_ctx *ctxs = NULL;

/*
 * Lock to serialize access to the linked list.
 */
static DEFINE_MUTEX_W_UNLOCKED(ctxs_lock);

/*
 * Thread ID of the signal handler thread.
 */
static pthread_t sig_thread;
static atomic_bool_t sig_thread_init = ATOMIC_BOOL_INIT(false);

/*
 * Is signal processing performed?
 */
static atomic_bool_t sig_raised = ATOMIC_BOOL_INIT(false);

bool sig_handler_active(void)
{
	return atomic_bool_read(&sig_raised);
}

/* DELETE /testSessions/<testSessionId> */
static int acvp_cancel(struct acvp_testid_ctx *testid_ctx, int sig)
{
	const struct acvp_ctx *ctx;
	const struct acvp_net_ctx *net;
	struct acvp_auth_ctx *auth = NULL;
	struct acvp_na_ex netinfo;
	char url[ACVP_NET_URL_MAXLEN];
	int ret = 0;

	if (!testid_ctx)
		return 0;

	if (!testid_ctx->testid)
		return 0;

	/* In case of SIGSTOP, do not cancel the request */
	if (sig == SIGQUIT || !testid_ctx->sig_cancel_send_delete)
		goto out;

	auth = testid_ctx->server_auth;
	ctx = testid_ctx->ctx;
	if (!ctx)
		return 0;

	if (!auth || !auth->jwt_token || !auth->jwt_token_len) {
		logger(LOGGER_VERBOSE, LOGGER_C_SIGNALHANDLER,
		       "No authentication context found for cancel operation\n");
		return 0;
	}

	CKINT(acvp_get_net(&net));

	CKINT(acvp_testid_url(testid_ctx, url, sizeof(url)));

	logger_status(LOGGER_C_SIGNALHANDLER,
		      "Cancel outstanding request context with ACVP server\n");

	/* Do not use auth context lock as we terminate anyway. */
	netinfo.net = net;
	netinfo.url = url;
	netinfo.server_auth = auth;
	ret = na->acvp_http_delete(&netinfo);

out:
	acvp_release_auth(testid_ctx);
	acvp_release_testid(testid_ctx);
	return ret;
}

/*****************************************************************************
 * Signal handler
 *****************************************************************************/

void sig_enqueue_ctx(struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_testid_ctx *tmp, *prev = NULL;

	if (!testid_ctx)
		return;

	testid_ctx->next = NULL;

	mutex_w_lock(&ctxs_lock);

	/* Check that ctx was enqueued in the first place */
	for (tmp = ctxs; tmp != NULL; tmp = tmp->next) {
		if (tmp == testid_ctx)
			break;

		prev = tmp;
	}

	/* do not double-enqueue */
	if (tmp) {
		mutex_w_unlock(&ctxs_lock);
		return;
	}

	if (prev)
		prev->next = testid_ctx;
	else
		ctxs = testid_ctx;

	mutex_w_unlock(&ctxs_lock);
}

void sig_dequeue_ctx(struct acvp_testid_ctx *testid_ctx)
{
	struct acvp_testid_ctx *tmp, *prev = NULL;

	if (!testid_ctx)
		return;

	mutex_w_lock(&ctxs_lock);

	/* Check that ctx was enqueued in the first place */
	for (tmp = ctxs; tmp != NULL; tmp = tmp->next) {
		if (tmp == testid_ctx)
			break;

		prev = tmp;
	}

	/* ctx was not enqueued */
	if (!tmp) {
		mutex_w_unlock(&ctxs_lock);
		return;
	}

	if (prev)
		prev->next = testid_ctx->next;
	else
		ctxs = testid_ctx->next;

	mutex_w_unlock(&ctxs_lock);

	testid_ctx->next = NULL;
}

static void sig_term_unthreaded(int sig)
{
	/* Wait sleep time plus some grace time after sending cancel. */
	const struct timespec wait = { .tv_sec = SLEEP_SLEEPTIME_SECONDS,
				       .tv_nsec = 1<<20 };
	struct acvp_testid_ctx *ctx;
	uint32_t testids[ACVP_REQ_MAX_FAILED_TESTID];
	unsigned int testid_idx = 0;

	acvp_op_interrupt();
	na->acvp_http_interrupt();
	/* Wait until all threads had time to process interrupt. */
	nanosleep(&wait, NULL);

	logger_status(LOGGER_C_SIGNALHANDLER,
		      "Canceling the outstanding download operations\n");

	mutex_w_lock(&ctxs_lock);
	ctx = ctxs;
	while (ctx) {
		struct acvp_testid_ctx *tmp;

		if (ctx->testid && (sig == SIGQUIT)) {
			if (testid_idx >= ACVP_REQ_MAX_FAILED_TESTID) {
				logger(LOGGER_ERR, LOGGER_C_SIGNALHANDLER,
				       "Programming error: size of threads array too small!\n");
			} else {
				testids[testid_idx] = ctx->testid;
				testid_idx++;
			}
		}

		tmp = ctx;
		ctx = ctx->next;

		// TODO: we may leak one or more struct acvp_vsid_ctx here in case the acvp_testid_ctx is wrapped by one or more acvp_vsid_ctx. But this is harmless as we are going to terminate anyway.
		acvp_cancel(tmp, sig);
	}
	mutex_w_unlock(&ctxs_lock);

	if (testid_idx) {
		unsigned int i;

		fprintf(stderr,
			"Not all testIDs were processed cleanly. Invoke ACVP Proxy with the following options to continue processing the remaining test vectors possibly with the --request option:\n");

		for (i = 0; i < testid_idx; i++)
			printf("--testid %u ", testids[i]);

		printf("\n");
	}

	acvp_def_release_all();
	totp_release_seed();
}

/* Signal handler for a grave fault: clean up message queue */
static void sig_fault(int sig)
{
	totp_release_seed();
	exit(sig);
}

static void sig_cleanup(int sig)
{
	atomic_bool_set_true(&sig_raised);

#ifdef ACVP_USE_PTHREAD
	/*
	 * Clean up the system threads - all other cleanups are done by signal
	 * handler thread.
	 */
	thread_release(true, true);
#else
	/*
	 * Set new signal handler that allow the immediate termination of the
	 * application. I.e. the first signal handler logic sending
	 * the cancel operation can be terminated.
	 */
	signal(SIGHUP, sig_fault);
	signal(SIGINT, sig_fault);
	signal(SIGQUIT, sig_fault);
	signal(SIGTERM, sig_fault);

	/* General cleanup */
	sig_term_unthreaded(sig);
#endif
	exit(sig);
}

/* Master thread signal handler to cleanup all threads */
ACVP_DEFINE_CONSTRUCTOR(install_signal)
static void install_signal(void)
{
	logger(LOGGER_DEBUG, LOGGER_C_SIGNALHANDLER, "Install signal handler\n");
	signal(SIGHUP, sig_cleanup);
	signal(SIGINT, sig_cleanup);
	signal(SIGQUIT, sig_cleanup);
	signal(SIGTERM, sig_cleanup);

	signal(SIGSEGV, sig_fault);
}

#ifdef ACVP_USE_PTHREAD
/* Signal handler thread to clean up all except the system threads */
static int sig_handler_thread(void *arg)
{
	sigset_t signals, unblock, old;
	int ret, sig;

	(void)arg;

	sig_thread = pthread_self();
	atomic_bool_set_true(&sig_thread_init);

	/* Enable signals for the signal thread. */
	sigemptyset(&signals);
	sigaddset(&signals, SIGUSR1);
	sigaddset(&signals, SIGHUP);
	sigaddset(&signals, SIGINT);
	sigaddset(&signals, SIGQUIT);
	sigaddset(&signals, SIGTERM);
	sigaddset(&signals, SIGSEGV);

	logger(LOGGER_VERBOSE, LOGGER_C_SIGNALHANDLER, "thread initialized\n");

	/* Block until we receive a signal */
	ret = sigwait(&signals, &sig);
	if (ret)
		goto out;

	/* SIGUSR1 simply terminates the sighandler thread */
	if (sig == SIGUSR1)
		goto out;

	/* SIGSEGV means we have a serious issue - only clean up the MQ */
	if (sig == SIGSEGV) {
		sig_fault(sig);
		/* NOTREACHED */
		exit(sig);
	}

	atomic_bool_set_true(&sig_raised);

	/*
	 * Re-enable following signals globally to allow subsequent signals
	 * to forcefully terminate the application. This is useful if the
	 * HTTP network operation takes too long or has other issues.
	 */
	sigemptyset(&unblock);
	sigaddset(&unblock, SIGHUP);
	sigaddset(&unblock, SIGINT);
	sigaddset(&unblock, SIGQUIT);
	sigaddset(&unblock, SIGTERM);
	ret = -pthread_sigmask(SIG_UNBLOCK, &unblock, &old);
	if (ret)
		goto out;
	signal(SIGHUP, sig_fault);
	signal(SIGINT, sig_fault);
	signal(SIGQUIT, sig_fault);
	signal(SIGTERM, sig_fault);

	logger(LOGGER_VERBOSE, LOGGER_C_SIGNALHANDLER,
	       "Shutting down cleanly but forcefully\n");
	/* Process signal: Clean up all user threads */
	thread_release(true, false);
	/* Process signal: Cleanup all non-threading work */
	sig_term_unthreaded(sig);

out:
	logger(LOGGER_VERBOSE, LOGGER_C_SIGNALHANDLER, "thread terminated\n");
	return 0;
}
#endif

int sig_install_handler(void)
{
#ifdef ACVP_USE_PTHREAD
	sigset_t block, old;
	int ret;

	/*
	 * Block signals for the main thread. This is necessary to prevent
	 * the kernel from not scheduling the threads. The signal() registered
	 * signals are delivered to the master thread once the signal thread
	 * receives the signals.
	 */
	sigfillset(&block);
	ret = -pthread_sigmask(SIG_BLOCK, &block, &old);
	if (ret)
		return ret;

	return thread_start(sig_handler_thread, NULL,
			    ACVP_THREAD_SIGHANDLER_GROUP, NULL);
#else
	return 0;
#endif
}

void sig_uninstall_handler(void)
{
	if (atomic_bool_read(&sig_thread_init)) {
		atomic_bool_set_false(&sig_thread_init);
		pthread_kill(sig_thread, SIGUSR1);
	}
}
