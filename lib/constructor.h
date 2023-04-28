/*
 * Copyright (C) 2018 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef CONSTRUCTOR_H
#define CONSTRUCTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ >= 7)

#if defined(ACVPPROXY_EXTENSION)

#define ACVP_DEFINE_CONSTRUCTOR(_func)                                         \
	static void __attribute__((unused)) _func(void);
#define ACVP_DEFINE_DESTRUCTOR(_func)                                          \
	static void __attribute__((unused)) _func(void);
#else

#define ACVP_DEFINE_CONSTRUCTOR(_func)                                         \
	static void __attribute__((constructor)) _func(void);
#define ACVP_DEFINE_DESTRUCTOR(_func)                                          \
	static void __attribute__((destructor)) _func(void);

#endif

#else

#error "Constructor / destructor not defined for compiler"

#endif

#ifdef __cplusplus
}
#endif

#endif /* CONSTRUCTOR_H */
