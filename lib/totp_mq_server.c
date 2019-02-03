/* TOTP message queue server
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
#include <stdlib.h>
#include <unistd.h>

/* Message queue code */
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "atomic_bool.h"
#include "bool.h"
#include "config.h"
#include "logger.h"
#include "mutex.h"
#include "sleep.h"
#include "ret_checkers.h"
#include "totp.h"
#include "totp_mq_server.h"
#include "threading_support.h"

/****************************************************************************
 * Message queue server and client to deliver TOTP value
 *
 * It is required that only one TOTP value is created from a seed within
 * 30 seconds. If multiple processes are spawned, one process must take the
 * lead on generating the TOTP value to guarantee that only one TOTP value
 * is truly generated from a seed within 30 seconds.
 *
 * To ensure that only one entity creates a TOTP value using one seed,
 * the first ACVP proxy process tries to establish a message queue server
 * executing as a thread in that process. This process but also all other
 * ACVP processes implement a message queue client. The MQ server hands out
 * the TOTP value to the client once the client pings them.
 *
 * If the first ACVP proxy process terminates, it also terminates the TOTP
 * server. This implies that another process will try to start the server
 * thread.
 ****************************************************************************/

#ifdef ACVP_TOTP_MQ_SERVER

#define TOTP_MQ_NAME		"/"
#define TOTP_MQ_PROJ_ID		1122334455
#define TOTP_MSG_TYPE_PING	1 /* Ping from client to server, no data */
#define TOTP_MSG_TYPE_TOTP	2 /* Message from server to client with TOTP */

static int mq_server = -1;
static int mq_client = -1;

/*
 * Mutex guards the mq_server / mq_client descriptors as well as the associated
 * message queues.
 */
static DEFINE_MUTEX_UNLOCKED(mq_lock);

static atomic_bool_t mq_shutdown = ATOMIC_BOOL_INIT(false);

/*
 * Message buffer to be exchanged between client and server. Note, we do not
 * handle the endianess of totp_val as the message is only exchanged on the
 * local system. If that implementation changes where this message can
 * cross systems, the endianess matters!
 */
struct totp_msgbuf {
	long mtype;
	uint32_t totp_val;
};

struct totp_thread_ctx {
	bool wait_step;
};

/* TOTP server thread main loop */
static int totp_mq_server_thread(void *arg)
{
	struct totp_thread_ctx *ctx = arg;
	struct totp_msgbuf msg;
	ssize_t read;
	int ret = 0;
	bool wait_step = false;

	if (ctx) {
		wait_step = ctx->wait_step;
		free(ctx);
	}

	logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
	       "Server: message queue server initialized\n");

	/* Wait a step size as requested when instantiating server. */
	if (wait_step) {
		CKINT(sleep_interruptible(TOTP_STEP_SIZE, &mq_shutdown));
	}

	while (1) {
		unsigned int i = 0;
		int errsv;

		/* Wait for ping from client */
		msg.mtype = TOTP_MSG_TYPE_PING;
		mutex_reader_lock(&mq_lock);
		read = msgrcv(mq_server, (void *)&msg, sizeof(msg.totp_val),
			      TOTP_MSG_TYPE_PING, MSG_NOERROR);
		errsv = errno;

		/* Something during msgrcv went wrong. */
		if (read == -1) {
			mutex_reader_unlock(&mq_lock);
			if (errsv == EINTR) {
				continue;
			} else {
				ret = -errsv;
				goto out;
			}
		}

		/* Generate TOTP value */
		do {
			i++;
			ret = totp_get_val(&msg.totp_val);

			if (atomic_bool_read(&mq_shutdown)) {
				mutex_reader_unlock(&mq_lock);
				ret = -ESHUTDOWN;
				goto out;
			}

			if (ret) {
				logger(LOGGER_WARN, LOGGER_C_MQSERVER,
				       "Server: getting TOTP value failed for %uth time (%d)\n",
				       i, ret);
			}
		} while (i <= 10 && ret);

		if (ret)
			msg.totp_val = 0;

		/* Send TOTP value. */
		msg.mtype = TOTP_MSG_TYPE_TOTP;
		ret = msgsnd(mq_server, (void*)&msg, sizeof(msg.totp_val), 0);
		mutex_reader_unlock(&mq_lock);
		if (ret) {
			logger(LOGGER_WARN, LOGGER_C_MQSERVER,
			       "Server: sending TOTP value failed (%d)\n",
			       errno);
		} else {
			logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
			       "Server: TOTP value delivered to client\n");
		}
	}

out:
	logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,  "terminate server\n");

	/*
	 * Do not lock this operation as the invocation of the server already
	 * is performed with the lock taken.
	 */
	msgctl(mq_server, IPC_RMID, NULL);
	mq_server = -1;
	return ret;
}

static int totp_mq_start_server(bool wait_step)
{
	key_t key;
	int ret = 0;

	if (mq_server != -1)
		return 0;

	/* Generate message queue key that is known to everybody. */
	key = ftok(TOTP_MQ_NAME, TOTP_MQ_PROJ_ID);
	if (key == -1)
		return -errno;

	/* Create message queue. */
	mutex_lock(&mq_lock);
	mq_server = msgget(key, (IPC_CREAT | IPC_EXCL | 0600));
	mutex_unlock(&mq_lock);
	if (mq_server == -1) {
		int errsv = errno;

		/* Creation failed with an error other than EEXIST. */
		if (errsv != EEXIST) {
			logger(LOGGER_WARN, LOGGER_C_MQSERVER,
			       "Server: cannot create message queue (%d)\n",
			       -errsv);
			ret = -errsv;
			goto out;
		}

		/*
		 * If we reach here, EEXIST is returned -- we do not set up the
		 * server as another process set up the server already. Thus,
		 * we do not need to set it up again.
		 */

	} else {
		struct totp_thread_ctx *ctx;
		int ret_ancestor;

		/* Set up arguments for server thread. */
		ctx = calloc(1, sizeof(*ctx));
		CKNULL(ctx, -ENOMEM);

		ctx->wait_step = wait_step;

		/* Start server. */
		CKINT(thread_start(totp_mq_server_thread, ctx,
				   ACVP_THREAD_TOTP_SERVER_GROUP,
				   &ret_ancestor));

		if (ret_ancestor) {
			logger(LOGGER_WARN, LOGGER_C_MQSERVER,
			       "Server: TOTP server ancestor thread returned with %d\n",
			       ret_ancestor);
		}
	}

out:
	return ret;
}

static int totp_mq_start_client(void)
{
	key_t key;

	if (mq_client != -1)
		return 0;

	/* Generate message queue key that is known to everybody. */
	key = ftok(TOTP_MQ_NAME, TOTP_MQ_PROJ_ID);
	if (key == -1)
		return -errno;

	/*
	 * Attach to message queue. This message queue should always exist
	 * as the server thread was either started before us or during starting
	 * of the server thread it was identified that there is already a
	 * server.
	 */
	mutex_lock(&mq_lock);
	mq_client = msgget(key, 0);
	mutex_unlock(&mq_lock);
	if (mq_client == -1) {
		int errsv = -errno;

		/*
		 * There is a tiny race window: if during first server setup
		 * call the check identified that there is another server, but
		 * that server died before we are able to set up the client
		 * message queue, the client will not be initialized.
		 */
		if (errsv == -ENOENT) {
			/* Re-spawn server and client. */
			if (!totp_mq_start_server(true)) {
				mutex_lock(&mq_lock);
				mq_client = msgget(key, 0);
				mutex_unlock(&mq_lock);
				if (mq_client == -1)
					errsv = -errno;
				else
					goto success;
			}
		}

		logger(LOGGER_WARN, LOGGER_C_MQSERVER,
			"Client: Message queue client could not be initialized (%d)\n",
			errsv);
		return errsv;
	}

success:
	logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
	       "Client: Message queue client initialized\n");

	return 0;
}

static int totp_mq_start(bool restart)
{
	int ret;

	atomic_bool_set_false(&mq_shutdown);

	/* Terminate local client if exist. */
	if (mq_client != -1) {
		mutex_lock(&mq_lock);
		msgctl(mq_client, IPC_RMID, NULL);
		mq_client = -1;
		mutex_unlock(&mq_lock);
	}

	/* Start server. */
	CKINT(totp_mq_start_server(restart));

	/* Start client. */
	ret = totp_mq_start_client();

out:
	return ret;
}

int totp_mq_get_val(uint32_t *totp_val)
{
	struct totp_msgbuf msg;
	ssize_t read;
	unsigned int retries = 0;
	int ret;

	if (mq_client == -1) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* Loop to implement retry operation. */
	for (retries = 0; retries < 60; retries++) {
		if (atomic_bool_read(&mq_shutdown)) {
			ret = -ESHUTDOWN;
			goto out;
		}

		/* Ping server to send us something */
		logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
		       "Client: Requesting TOTP value from message queue server\n");

		msg.mtype = TOTP_MSG_TYPE_PING;
		msg.totp_val = 0;

		mutex_reader_lock(&mq_lock);
		ret = msgsnd(mq_client, (void *)&msg, sizeof(msg.totp_val), 0);
		if (ret) {
			int errsv = errno;

			mutex_reader_unlock(&mq_lock);

			/*
			 * EINVAL is returned on Linux when the server died
			 */
			if ((errsv == EIDRM || errsv == EINVAL) &&
			    !atomic_bool_read(&mq_shutdown)) {
				/* Server died? If so, try to restart it. */
				logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
				       "TOTP client: Trying to respawn message queue server and client\n");
				CKINT(totp_mq_start(true));
			}

			continue;
		}

		/* Get TOTP value from server */
		msg.mtype = TOTP_MSG_TYPE_TOTP;

		/* Use a busy-wait loop to monitor mq_shutdown. */
		while (1) {
			const struct timespec sleeptime = {.tv_sec = 0,
							   .tv_nsec = 1 << 27 };

			read = msgrcv(mq_client, (void *)&msg,
				      sizeof(msg.totp_val),
				      TOTP_MSG_TYPE_TOTP,
				      MSG_NOERROR | IPC_NOWAIT);

			if (read > 0)
				break;
			if (atomic_bool_read(&mq_shutdown)) {
				ret = -ESHUTDOWN;
				goto out;
			}

			if (read < 0 && errno != ENOMSG)
				break;
			nanosleep(&sleeptime, NULL);
		}

		mutex_reader_unlock(&mq_lock);

		if (read != sizeof(msg.totp_val)) {
			if (errno == ENOMSG) {
				/* Server did not deliver information */
				CKINT(sleep_interruptible(1, &mq_shutdown));
				continue;
			} else if (errno == EIDRM) {
				/* Server died */
				continue;
			}
		}

		if (msg.totp_val == 0) {
			/* Server died? If so, try to restart it. */
			logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
			       "Client: Trying to respawn message queue server and client\n");
			CKINT(totp_mq_start(true));

			continue;
		}

		logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
		       "Client: Received TOTP value from message queue server\n");
		if (totp_val)
			*totp_val = msg.totp_val;

		return 0;
	}

	logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
	       "TOTP client: Trying to respawn message queue server and client\n");
	ret = -EFAULT;

out:
	logger(LOGGER_WARN, LOGGER_C_MQSERVER,
	       "Client: Failure to get TOTP value from message queue server\n");

	return ret;
}

void totp_mq_release(void)
{
	atomic_bool_set_true(&mq_shutdown);

	if (mq_server != -1) {
		/*
		 * In case the server thread was canceled, clean up the message
		 * queue here which also causes the server to terminate.
		 */
		msgctl(mq_server, IPC_RMID, NULL);
		mq_server = -1;
	}

	/* NO cleanup of mq_client as this will impact the server! */
}

int totp_mq_init(void)
{
	return totp_mq_start(false);
}

#else /* ACVP_TOTP_MQ_SERVER */

int totp_mq_init(void)
{
	return 0;
}

void totp_mq_release(void)
{
}

int totp_mq_get_val(uint32_t *totp_val)
{
	(void)totp_val;
	return -EOPNOTSUPP;
}

#endif /* ACVP_TOTP_MQ_SERVER */
