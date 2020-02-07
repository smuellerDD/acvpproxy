/* TOTP message queue server
 *
 * Copyright (C) 2018 - 2020, Stephan Mueller <smueller@chronox.de>
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
#include <string.h>
#include <unistd.h>

/* Message queue code */
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "atomic.h"
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
 *
 * Two message queues are used to implement two unidirectional links between
 * the server and the client. This ensures unlimited scalability: the client to
 * server MQ may be congested in case of a high volume of TOTP requests.
 * Even with a congested connection for requesting a TOTP value, the server
 * to client MQ will never be congested ensuring that a generated TOTP
 * value always reaches one client.
 ****************************************************************************/

#ifdef ACVP_TOTP_MQ_SERVER

#define TOTP_MQ_NAME		"/"
#define TOTP_MQ_PROJ_ID_SC	1122334455	/* Server to client */
#define TOTP_MQ_PROJ_ID_CS	1122334466	/* Client to server */
#define TOTP_MSG_TYPE_PING	1 /* Ping from client to server, no data */
#define TOTP_MSG_TYPE_TOTP	2 /* Message from server to client with TOTP */

/* Server RX descriptor - connected to client TX descriptor */
static atomic_t mq_srv_rx = ATOMIC_INIT(-1);
/* Server TX descriptor - connected to client RX descriptor */
static atomic_t mq_srv_tx = ATOMIC_INIT(-1);
/* Client TX descriptor - connected to server RX descriptor */
static atomic_t mq_cln_tx = ATOMIC_INIT(-1);
/* Client RX descriptor - connected to server TX descriptor */
static atomic_t mq_cln_rx = ATOMIC_INIT(-1);

/*
 * Mutex guards the mq_srv_* / mq_cln_* descriptors as well as
 * the associated message queues.
 */
static DEFINE_MUTEX_UNLOCKED(mq_lock);

/* Shall client shut down for good? */
static atomic_bool_t mq_client_shutdown = ATOMIC_BOOL_INIT(false);

/*
 * Is server alive? (If it is set to false from outside the server, the server
 * will shut down).
 */
static atomic_bool_t mq_server_alive = ATOMIC_BOOL_INIT(false);

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

/* Terminate one registered message queue */
static void totp_mq_terminate_ipc(atomic_t *mq)
{
	int curr_mq = atomic_read(mq);

	if (curr_mq != -1) {
		atomic_set(-1, mq);
		msgctl(curr_mq, IPC_RMID, NULL);
	}
}

/* We know that the message queue is terminated */
static void totp_mq_term_server(void)
{
	/* Stop a potential running TOTP request */
	totp_term();

	/* Reset the message queue descriptors */
	atomic_set(-1, &mq_cln_tx);
	atomic_set(-1, &mq_cln_rx);
	atomic_set(-1, &mq_srv_rx);
	atomic_set(-1, &mq_srv_tx);
}

/* TOTP server thread main loop */
static int totp_mq_server_thread(void *arg)
{
	struct totp_msgbuf msg;
	ssize_t read;
	int ret = 0;

	(void)arg;

	logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
	       "Server: message queue server initialized\n");

	while (1) {
		int errsv;

		/* Wait for ping from client */
		msg.mtype = TOTP_MSG_TYPE_PING;
		read = msgrcv(atomic_read(&mq_srv_rx),
			      (void *)&msg, sizeof(msg.totp_val),
			      TOTP_MSG_TYPE_PING, MSG_NOERROR);
		errsv = errno;

		/* Something during msgrcv went wrong. */
		if (read == -1) {
			if (errsv == EINTR) {
				continue;
			} else {
				ret = -errsv;
				goto out;
			}
		}

		/* Generate TOTP value - we usually sleep here. */
		CKINT_LOG(totp_get_val(&msg.totp_val),
			  "Server: getting TOTP value failed for (%d)\n", ret);

		/* Send TOTP value. */
		msg.mtype = TOTP_MSG_TYPE_TOTP;
		ret = msgsnd(atomic_read(&mq_srv_tx),
			     (void*)&msg, sizeof(msg.totp_val), 0);
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
	totp_mq_terminate_ipc(&mq_srv_rx);
	totp_mq_terminate_ipc(&mq_srv_tx);

	atomic_bool_set_false(&mq_server_alive);

	return ret;
}

/*
 * Is the message queue alive?
 *
 * If not, remove the message queue if exists to prevent having a stale MQ.
 *
 * We only check the MQ from client to server which is the busy one.
 */
static bool totp_is_mq_alive(void)
{
	struct msqid_ds mq_stat;
	time_t max_wait;
	int tmpmq;
	key_t key = ftok(TOTP_MQ_NAME, TOTP_MQ_PROJ_ID_CS);

	if (key == -1)
		return false;
	tmpmq = msgget(key, 0);

	/* Message queue does not exist */
	if (tmpmq == -1)
		return false;

	if (msgctl(tmpmq, IPC_STAT, &mq_stat))
		return false;

	max_wait = time(NULL);
	if (max_wait == (time_t)-1)
		return false;

	/* Give it some grace time of 2 seconds */
	max_wait -= TOTP_STEP_SIZE + 2;

	/*
	 * Remove message queue only if we have a stale message queue (data is
	 * in message queue, but no read/write for more than the TOTP step
	 * size).
	 */
	if (mq_stat.msg_qnum &&
	    mq_stat.msg_stime < max_wait &&
	    mq_stat.msg_rtime < max_wait) {
		msgctl(tmpmq, IPC_RMID, NULL);

		/* We terminate our server if running and reset MQ values */
		totp_mq_term_server();

		return false;
	}

	return true;
}

static int totp_mq_start_server(void)
{
	key_t key;
	int ret = 0;

	atomic_bool_set_false(&mq_client_shutdown);

	if (atomic_read(&mq_srv_rx) != -1)
		return EINTR;

	/* Generate message queue key that is known to everybody. */
	key = ftok(TOTP_MQ_NAME, TOTP_MQ_PROJ_ID_CS);
	if (key == -1)
		return -errno;

	/* Create message queue. */
	atomic_set(msgget(key, (IPC_CREAT | IPC_EXCL | 0600)), &mq_srv_rx);
	if (atomic_read(&mq_srv_rx) == -1) {
		int errsv = errno;

		/* Creation failed with an error other than EEXIST. */
		if (errsv != EEXIST) {
			logger(LOGGER_WARN, LOGGER_C_MQSERVER,
			       "Server: cannot create message queue (%d)\n",
			       -errsv);
			return -errsv;
		}

		/*
		 * If we reach here, EEXIST is returned -- in this case,
		 * we remove the message queue unconditionally when we start
		 * up. This implies that even a valid server is terminated and
		 * there is a new election process to start a new server.
		 */
		if (totp_is_mq_alive())
			return EINTR;
		else
			return EEXIST;

	} else {
		int ret_ancestor, tmpmq;
		
		/* Setup server TX queue */
		key = ftok(TOTP_MQ_NAME, TOTP_MQ_PROJ_ID_SC);
		if (key == -1) {
			ret = -errno;
			totp_mq_terminate_ipc(&mq_srv_rx);
			goto out;
		}
		
		/*
		 * Since we know at this point that we are providing
		 * the MQ server, delete any potentially existing sever to
		 * client MQ.
		 */
		tmpmq = msgget(key, 0);
		if (tmpmq != 1)
			msgctl(tmpmq, IPC_RMID, NULL);

		atomic_set(msgget(key, (IPC_CREAT | IPC_EXCL | 0600)),
			   &mq_srv_tx);
		if (atomic_read(&mq_srv_tx) == -1) {
			ret = -errno;
			totp_mq_terminate_ipc(&mq_srv_rx);
			goto out;
		}

		/* Start server. */
		CKINT(thread_start(totp_mq_server_thread, NULL,
				   ACVP_THREAD_TOTP_SERVER_GROUP,
				   &ret_ancestor));

		if (ret_ancestor) {
			logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
			       "Server: TOTP server ancestor thread returned with %d\n",
			       ret_ancestor);
		}
		logger(LOGGER_DEBUG, LOGGER_C_MQSERVER, "TOTP Server started\n");
	}

out:
	return ret;
}

static int totp_mq_start_client(void)
{
	key_t key;
	int ret = 0;

	atomic_bool_set_false(&mq_client_shutdown);

	if (atomic_read(&mq_cln_tx) != -1)
		return 0;

	/* Generate message queue key that is known to everybody. */
	key = ftok(TOTP_MQ_NAME, TOTP_MQ_PROJ_ID_CS);
	if (key == -1)
		return -errno;

	/*
	 * Attach to message queue. This message queue should always exist
	 * as the server thread was either started before us or during starting
	 * of the server thread it was identified that there is already a
	 * server.
	 */
	atomic_set(msgget(key, 0), &mq_cln_tx);
	if (atomic_read(&mq_cln_tx) == -1) {
		int errsv = -errno;

		/*
		 * There is a tiny race window: if during first server setup
		 * call the check identified that there is another server, but
		 * that server died before we are able to set up the client
		 * message queue, the client will not be initialized.
		 */
		if (errsv == -ENOENT)
			return EAGAIN;

		logger(LOGGER_WARN, LOGGER_C_MQSERVER,
		       "Client: Message queue client could not be initialized (%d)\n",
		       errsv);
		return errsv;
	}

	/* Set up the TOTP server to client queue */
	key = ftok(TOTP_MQ_NAME, TOTP_MQ_PROJ_ID_SC);
	if (key == -1)
		return EAGAIN;
	atomic_set(msgget(key, 0), &mq_cln_rx);
	if (atomic_read(&mq_cln_rx) == -1) {
		logger(LOGGER_WARN, LOGGER_C_MQSERVER,
		       "Client: Message queue client could not be initialized (%d)\n",
		       -errno);

		totp_mq_terminate_ipc(&mq_cln_tx);

		return EAGAIN;
	}

	return ret;
}

static int totp_mq_start(bool restart)
{
	unsigned int attempts = TOTP_STEP_SIZE * 2;
	int ret = 0;

	mutex_lock(&mq_lock);

	if (restart) {
		/* Check if MQ is alive and kill it if not */
		if (totp_is_mq_alive())
			goto out;

		totp_mq_term_server();

		logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
		       "TOTP Client: Trying to respawn message queue server and client\n");
	}

	do {
		if (restart)
			sleep_interruptible(1, &mq_client_shutdown);
		/* Terminate local client if exist. */
		totp_mq_terminate_ipc(&mq_cln_tx);
		totp_mq_terminate_ipc(&mq_cln_rx);

		/* Start server if not alive. */
		if (!atomic_bool_read(&mq_server_alive)) {
			do {
				if (restart)
					sleep_interruptible(1,
							    &mq_client_shutdown);

				atomic_bool_set_true(&mq_server_alive);
				ret = totp_mq_start_server();
				if (ret)
					atomic_bool_set_false(&mq_server_alive);

				if (ret < 0)
					goto out;

				restart = true;
			} while (ret == EEXIST && attempts--);
		}

		restart = true;

		/* Start client. */
		ret = totp_mq_start_client();
	} while (ret == EAGAIN && attempts--);

	if (ret == EAGAIN) {
		logger(LOGGER_ERR, LOGGER_C_MQSERVER,
		       "Failed to start the server and client\n");
		ret = -EOPNOTSUPP;

		totp_mq_term_server();
	}

out:
	mutex_unlock(&mq_lock);
	return ret;
}

int totp_mq_get_val(uint32_t *totp_val)
{
	struct totp_msgbuf msg;
	ssize_t read = 0;
	unsigned int retries = 0;
	int ret, errsv = 0;

	if ((atomic_read(&mq_cln_tx) == -1) ||
	    (atomic_read(&mq_cln_rx) == -1)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	/* Loop to implement retry operation. */
	for (retries = 0; retries < 60; retries++) {
		if (atomic_bool_read(&mq_client_shutdown)) {
			ret = -ESHUTDOWN;
			goto out;
		}

		/* Ping server to send us something */
		logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
		       "Client: Requesting TOTP value from message queue server\n");

		msg.mtype = TOTP_MSG_TYPE_PING;
		msg.totp_val = 0;

		ret = msgsnd(atomic_read(&mq_cln_tx),
			     (void *)&msg, sizeof(msg.totp_val), 0);
		if (ret) {
			errsv = errno;

			/*
			 * EINVAL is returned when the server died
			 */
			if ((errsv == EIDRM || errsv == EINVAL) &&
			    !atomic_bool_read(&mq_client_shutdown)) {
				CKINT(totp_mq_start(true));
			}

			continue;
		}

		/* Get TOTP value from server */
		msg.mtype = TOTP_MSG_TYPE_TOTP;

		/* Use a busy-wait loop to monitor mq_client_shutdown. */
		while (1) {
			const struct timespec sleeptime = {.tv_sec = 0,
							   .tv_nsec = 1 << 27 };

			if (!totp_is_mq_alive()) {
				ret = EAGAIN;
				break;
			}

			/*
			 * Poll for the TOTP value that the server should
			 * deliver at some point.
			 */
			read = msgrcv(atomic_read(&mq_cln_rx), (void *)&msg,
				      sizeof(msg.totp_val),
				      TOTP_MSG_TYPE_TOTP, IPC_NOWAIT);
			errsv = errno;

			/* Value received */
			if (read == sizeof(msg.totp_val)) {
				break;
			}

			if (atomic_bool_read(&mq_client_shutdown)) {
				ret = -ESHUTDOWN;
				goto out;
			}

			if (read < 0 &&
			    (errsv != ENOMSG &&
			     errsv != EINVAL &&
			     errsv != EINTR)) {
				break;
			}

			/* We got no message, sleep and then poll again. */
			nanosleep(&sleeptime, NULL);
		}

		/*
		 * The server and the message queue was re-initialized, so we
		 * need to re-send our TOTP request.
		 */
		if (ret == EAGAIN)
			continue;

		if (read != sizeof(msg.totp_val)) {
			if (errsv == EIDRM) {
				CKINT(totp_mq_start(true));
			}

			continue;
		}

		if (msg.totp_val == 0) {
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
	       "Client: Trying to respawn message queue server and client\n");
	ret = -EFAULT;

out:
	logger(LOGGER_VERBOSE, LOGGER_C_MQSERVER,
	       "Client: Failure to get TOTP value from message queue server %d\n", ret);

	return ret;
}

void totp_mq_release(void)
{
	atomic_bool_set_true(&mq_client_shutdown);
	atomic_bool_set_false(&mq_server_alive);

	/*
	 * In case the server thread was canceled, clean up the message
	 * queue here which also causes the server to terminate.
	 */
	totp_mq_terminate_ipc(&mq_srv_rx);

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
