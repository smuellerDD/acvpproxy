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

#include <errno.h>
#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <unistd.h>

#include "atomic_bool.h"
#include "compiler.h"
#include "config.h"
#include "logger.h"
#include "mutex_w.h"
#include "hash/hmac.h"
#include "hash/sha256.h"
#include "hash/memset_secure.h"
#include "sleep.h"
#include "ret_checkers.h"
#include "totp.h"
#include "totp_mq_server.h"

/*
 * Shared secret K for TOTP
 */
static uint8_t *totp_K = NULL;
static size_t totp_Klen = 0;

/*
 * When was the last TOTP value generated?
 */
static time_t totp_last_generated = 0;

/*
 * Callback to invoke when a new TOTP value is generated to store
 * the current time.
 */
static void (*totp_last_gen_cb)(time_t now) = NULL;

/*
 * Lock for the static variables above.
 */
static DEFINE_MUTEX_W_UNLOCKED(totp_lock);

/*
 * Break the waiting loop if the TOTP generator shall shut down.
 */
static atomic_bool_t totp_shutdown = ATOMIC_BOOL_INIT(false);

#if (GCC_VERSION >= 40400) || defined(__clang__)
#define __HAVE_BUILTIN_BSWAP32__
#define __HAVE_BUILTIN_BSWAP64__
#endif

#ifdef __HAVE_BUILTIN_BSWAP64__
#define _swap64(x) (uint64_t) __builtin_bswap64((uint64_t)(x))
#else

/****************
 * Rotate the 32 bit unsigned integer X by N bits left/right
 */
static inline uint32_t rol(uint32_t x, int n)
{
	return ((x << (n & (32 - 1))) | (x >> ((32 - n) & (32 - 1))));
}

static inline uint32_t ror(uint32_t x, int n)
{
	return ((x >> (n & (32 - 1))) | (x << ((32 - n) & (32 - 1))));
}

/* Byte swap for 32-bit and 64-bit integers. */
static inline uint32_t _bswap32(uint32_t x)
{
	return (uint32_t)((rol(x, 8) & 0x00ff00ffL) |
			  (ror(x, 8) & 0xff00ff00L));
}

static inline uint64_t _bswap64(uint64_t x)
{
	return ((uint64_t)_bswap32((uint32_t)x) << 32) |
	       (uint64_t)(_bswap32((uint32_t)(x >> 32)));
}

#define _swap64(x) _bswap64(x)
#endif

/* Endian dependent byte swap operations.  */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define be_bswap64(x) ((uint64_t)(x))
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define be_bswap64(x) _swap64(x)
#else
#error "Endianess not defined"
#endif

#ifdef ACVP_AUTHENTICATION_DEBUG

static uint64_t totp_counter_value, totp_counter_value_stepped;
static void totp_debug_store_counter(uint64_t val)
{
	totp_counter_value = val;
}

static void totp_debug_store_counter_stepped(uint64_t val)
{
	totp_counter_value_stepped = val;
}

void totp_debug_get_counter(uint64_t *counter, uint64_t *counter_stepped);
void totp_debug_get_counter(uint64_t *counter, uint64_t *counter_stepped)
{
	*counter = totp_counter_value;
	*counter_stepped = totp_counter_value_stepped;
}

#else /* ACVP_AUTHENTICATION_DEBUG */

static void totp_debug_store_counter(uint64_t val)
{
	(void)val;
}
static void totp_debug_store_counter_stepped(uint64_t val)
{
	(void)val;
}
void totp_debug_get_counter(uint64_t *counter, uint64_t *counter_stepped)
{
	*counter = 0;
	*counter_stepped = 0;
}

#endif /* ACVP_AUTHENTICATION_DEBUG */

/****************************************************************************
 * RFC 4226
 ****************************************************************************/
static int hotp(const uint8_t *hmac_key, size_t hmac_key_len, uint64_t counter,
		uint32_t digits, uint32_t *hotp_val)
{
	uint32_t offset, truncated, modulo = 1;
	uint8_t md[SHA_MAX_SIZE_DIGEST];

	/* calculate the modulo value */
	while (digits > 0) {
		modulo *= 10;
		digits--;
	}

	/* convert counter into network-byte order */
	counter = be_bswap64(counter);

	/* HMAC */
	hmac(sha256, hmac_key, hmac_key_len, (uint8_t *)&counter,
	     sizeof(counter), md);

	/* DT */
	offset = md[sha256->digestsize - 1] & 0xf;
	truncated = (uint32_t)((md[offset] & 0x7f) << 24) |
		    (uint32_t)((md[offset + 1] & 0xff) << 16) |
		    (uint32_t)((md[offset + 2] & 0xff) << 8) |
		    (uint32_t)((md[offset + 3] & 0xff));

	*hotp_val = truncated % modulo;

	memset_secure(md, 0, sizeof(md));

	return 0;
}

/****************************************************************************
 * RFC 6238
 ****************************************************************************/
static int _totp(const uint8_t *hmac_key, size_t hmac_key_len, uint32_t step,
		 uint32_t digits, uint32_t *totp_val)
{
	time_t now;
	uint64_t counter;

	/* Get time in seconds since Epoch */
	now = time(NULL);
	if (now == (time_t)-1)
		return -errno;

	totp_last_generated = now;

	counter = (uint64_t)now;
	totp_debug_store_counter(counter);

	counter /= step;
	totp_debug_store_counter_stepped(counter);

	return hotp(hmac_key, hmac_key_len, counter, digits, totp_val);
}

/*
 * Return number of seconds to sleep before retrying the TOTP value.
 */
static inline unsigned int totp_wait_time(time_t now)
{
	/* If we get an error, let the caller try again later */
	if (now == (time_t)-1)
		return TOTP_STEP_SIZE;

	now -= totp_last_generated;

	if (now > TOTP_STEP_SIZE)
		return 0;

	return (unsigned int)(TOTP_STEP_SIZE - now);
}

int totp_get_val(uint32_t *totp_val)
{
	time_t now;
	unsigned int wait_time;
	int ret;

	mutex_w_lock(&totp_lock);

	if (!totp_K || !totp_Klen || !totp_val) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Only generate a TOTP value if we generate a new one compared to the
	 * last generated value. This call also serializes parallel TOTP
	 * requests.
	 */
	now = time(NULL);
	while ((wait_time = totp_wait_time(now))) {
		mutex_w_unlock(&totp_lock);
		logger(LOGGER_VERBOSE, LOGGER_C_TOTP,
		       "sleeping for %u seconds\n", wait_time);

		CKINT(sleep_interruptible(wait_time, &totp_shutdown));

		mutex_w_lock(&totp_lock);
		now = time(NULL);
	}

	ret = _totp(totp_K, totp_Klen, TOTP_STEP_SIZE, TOTP_NUMBER_DIGITS,
		    totp_val);

	if (totp_last_gen_cb)
		totp_last_gen_cb(totp_last_generated);

out:
	atomic_bool_set_false(&totp_shutdown);
	mutex_w_unlock(&totp_lock);

	/* Make sure the sleep interruption is not turned into an error */
	if (ret == -EINTR)
		ret = 0;

	return ret;
}

/****************************************************************************
 * Interface code
 ****************************************************************************/
int totp(uint32_t *totp_val)
{
	int ret;

	logger_status(LOGGER_C_MQSERVER, "Requesting OTP value, waiting ...\n");

	ret = totp_mq_get_val(totp_val);
	/* If we get a shutdown signal, stop any processing. */
	if (ret == -ESHUTDOWN)
		return ret;
	else if (ret)
		return totp_get_val(totp_val);

	return 0;
}

static void __totp_release_seed(void)
{
	/*
	 * Guard the TOTP seed as mandated by NIST.
	 * This call securely erases the memory with the seed data before
	 * releasing.
	 */
	if (totp_K) {
		memset_secure(totp_K, 0, totp_Klen);
		free(totp_K);
		totp_K = NULL;
	}

	totp_Klen = 0;
}

void totp_term(void)
{
	atomic_bool_set_true(&totp_shutdown);
}

void totp_release_seed(void)
{
	totp_term();
	totp_mq_release();

	mutex_w_lock(&totp_lock);
	__totp_release_seed();
	mutex_w_unlock(&totp_lock);
}

/**
 * Guard the TOTP seed as mandated by NIST.
 * This function prevents strace or debugging of the process.
 */
static int totp_protection(void)
{
#ifdef __linux__
#ifndef DEBUG
	/*
	 * Disable the dumping of this process as we handle with keys. To
	 * support multiple invocations of this function, only disable the
	 * dumping if it has not already been disabled.
	 */
	/*
	 * WARNING: If you want to GDB the process, this call must be
	 * disabled.
	 */
	if (prctl(PR_GET_DUMPABLE) && prctl(PR_SET_DUMPABLE, 0) < 0)
		return -EOPNOTSUPP;
#endif
#endif

	return 0;
}

int totp_set_seed(const uint8_t *K, size_t Klen, time_t last_gen,
		  bool production, void (*last_gen_cb)(const time_t now))
{
	int ret;

	if (!K || !Klen)
		return -EINVAL;

	mutex_w_lock(&totp_lock);

	__totp_release_seed();

	CKINT(totp_protection());

	totp_K = malloc(Klen);
	CKNULL(totp_K, -errno);

	/*
	 * Guard the TOTP seed as mandated by NIST.
	 * This call prevents paging out of seed memory.
	 */
	ret = mlock(totp_K, Klen);
	if (ret) {
		ret = -errno;
		goto out;
	}

	memcpy(totp_K, K, Klen);

	totp_Klen = Klen;
	totp_last_generated = last_gen;
	totp_last_gen_cb = last_gen_cb;

	ret = totp_mq_init(production);

out:
	mutex_w_unlock(&totp_lock);
	return ret;
}
