// Copyright (c) 2012, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef GOOGLE_BREAKPAD_COMMON_ANDROID_INCLUDE_UCONTEXT_H
#define GOOGLE_BREAKPAD_COMMON_ANDROID_INCLUDE_UCONTEXT_H

#include <sys/cdefs.h>

#ifdef __BIONIC_UCONTEXT_H
#include <ucontext.h>
#else

#include <sys/ucontext.h>

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

// Provided by src/android/common/breakpad_getcontext.S
/*
#define  UCONTEXT_SIGMASK_OFFSET     40

#define  MCONTEXT_GREGS_OFFSET       184
#define  MCONTEXT_SP_OFFSET          432
#define  MCONTEXT_PC_OFFSET          440
#define  MCONTEXT_PSTATE_OFFSET      448
#define  MCONTEXT_EXTENSION_OFFSET   464

#define  FPSIMD_MAGIC                0x46508001

#define  FPSIMD_CONTEXT_MAGIC_OFFSET 0
#define  FPSIMD_CONTEXT_SIZE_OFFSET  4
#define  FPSIMD_CONTEXT_FPSR_OFFSET  8
#define  FPSIMD_CONTEXT_FPCR_OFFSET  12
#define  FPSIMD_CONTEXT_VREGS_OFFSET 16
#define  FPSIMD_CONTEXT_SIZE         528

#define  REGISTER_SIZE               8
#define  SIMD_REGISTER_SIZE          16


*/
int breakpad_getcontext(ucontext_t* ucp){


#if defined(__aarch64__)
asm volatile(
	"str	  xzr,		[x0, 184] \n "
	"stp	  x18, x19, [x0, 184 + 18 * 8] \n "
	"stp	  x20, x21, [x0, 184 + 20 * 8] \n "
	"stp	  x22, x23, [x0, 184 + 22 * 8] \n "
	"stp	  x24, x25, [x0, 184 + 24 * 8] \n "
	"stp	  x26, x27, [x0, 184 + 26 * 8] \n "
	"stp	  x28, x29, [x0, 184 + 28 * 8] \n "
	"str	  x30, 	 [x0, 184 + 30 * 8] \n "
	"str	  x30, [x0, 440] \n "
	"mov	  x2, sp  \n "
	"str	  x2, [x0, 432] \n "
    "str	  xzr, [x0, 448] \n "
	"add	  x2, x0, #464 \n "
	"mov	  w3, #(0x46508001 & 0xffff) \n "
	"movk	  w3, #(0x46508001 >> 16), lsl #16 \n "
	"str	  w3, [x2, #0] \n "
	"mov	  w3, #528 \n "
	"str	  w3, [x2, #4] \n "
	"add	  x3, x2, #(16 + 8 * 16) \n "
	"stp	  d8,  d9, [x3], #(2 * 16) \n "
	"stp	  d10, d11, [x3], #(2 * 16) \n "
	"stp	  d12, d13, [x3], #(2 * 16) \n "
	"stp	  d14, d15, [x3], #(2 * 16) \n "
	"add	  x3, x2, 8 \n "
	"mrs	  x4, fpsr \n "
	"str	  w4, [x3] \n "
	"mrs	  x4, fpcr \n "
	"str	  w4, [x3, 12 - 8] \n "
	"add	  x2, x2, #528 \n "
	"str	  xzr, [x2, #0] \n "
	"str	  xzr, [x2, #4] \n "
	"add	  x2, x0, #40 \n "
	"mov	  x0, #0 \n "  
	"mov	  x1, #0 \n "  
	"mov	  x3, #8 \n "
	"mov	  x8, #135 \n "
	"svc	  0 \n "
	/*"mov	  x0, 0 \n "*/
	   : 
       : 
       : "memory", "x0", "x1", "x2", "x3","x4", "x18","x19","x20","x21","x22","x23","x24","x25","x26","x27","x28","x29","x30","w3","w4","d8","d9","d11","d12","d13","d14","d15"
	 );
	return 0;
#elif defined(__x86_64__)
#else
#error "breakpad_getcontext is not support, please rewrite!\r\n"
#endif
#if 0
#define  _NSIG                       64
#define  __NR_rt_sigprocmask         135
	
	  .text
	  .global breakpad_getcontext
	  .hidden breakpad_getcontext
	  .type breakpad_getcontext, #function
	  .align 4
	  .cfi_startproc
	breakpad_getcontext:
	
	  /* The saved context will return to the getcontext() call point
		 with a return value of 0 */
	  str	  xzr,		[x0, MCONTEXT_GREGS_OFFSET +  0 * REGISTER_SIZE]
	
	  stp	  x18, x19, [x0, MCONTEXT_GREGS_OFFSET + 18 * REGISTER_SIZE]
	  stp	  x20, x21, [x0, MCONTEXT_GREGS_OFFSET + 20 * REGISTER_SIZE]
	  stp	  x22, x23, [x0, MCONTEXT_GREGS_OFFSET + 22 * REGISTER_SIZE]
	  stp	  x24, x25, [x0, MCONTEXT_GREGS_OFFSET + 24 * REGISTER_SIZE]
	  stp	  x26, x27, [x0, MCONTEXT_GREGS_OFFSET + 26 * REGISTER_SIZE]
	  stp	  x28, x29, [x0, MCONTEXT_GREGS_OFFSET + 28 * REGISTER_SIZE]
	  str	  x30,		[x0, MCONTEXT_GREGS_OFFSET + 30 * REGISTER_SIZE]
	
	  /* Place LR into the saved PC, this will ensure that when
		 switching to this saved context with setcontext() control
		 will pass back to the caller of getcontext(), we have
		 already arranged to return the appropriate return value in x0
		 above.  */
	  str	  x30, [x0, MCONTEXT_PC_OFFSET]
	
	  /* Save the current SP */
	  mov	  x2, sp
	  str	  x2, [x0, MCONTEXT_SP_OFFSET]
	
	  /* Initialize the pstate.  */
	  str	  xzr, [x0, MCONTEXT_PSTATE_OFFSET]
	
	  /* Figure out where to place the first context extension
		 block.  */
	  add	  x2, x0, #MCONTEXT_EXTENSION_OFFSET
	
	  /* Write the context extension fpsimd header.  */
	  mov	  w3, #(FPSIMD_MAGIC & 0xffff)
	  movk	  w3, #(FPSIMD_MAGIC >> 16), lsl #16
	  str	  w3, [x2, #FPSIMD_CONTEXT_MAGIC_OFFSET]
	  mov	  w3, #FPSIMD_CONTEXT_SIZE
	  str	  w3, [x2, #FPSIMD_CONTEXT_SIZE_OFFSET]
	
	  /* Fill in the FP SIMD context.  */
	  add	  x3, x2, #(FPSIMD_CONTEXT_VREGS_OFFSET + 8 * SIMD_REGISTER_SIZE)
	  stp	  d8,  d9, [x3], #(2 * SIMD_REGISTER_SIZE)
	  stp	  d10, d11, [x3], #(2 * SIMD_REGISTER_SIZE)
	  stp	  d12, d13, [x3], #(2 * SIMD_REGISTER_SIZE)
	  stp	  d14, d15, [x3], #(2 * SIMD_REGISTER_SIZE)
	
	  add	  x3, x2, FPSIMD_CONTEXT_FPSR_OFFSET
	
	  mrs	  x4, fpsr
	  str	  w4, [x3]
	
	  mrs	  x4, fpcr
	  str	  w4, [x3, FPSIMD_CONTEXT_FPCR_OFFSET - FPSIMD_CONTEXT_FPSR_OFFSET]
	
	  /* Write the termination context extension header.  */
	  add	  x2, x2, #FPSIMD_CONTEXT_SIZE
	
	  str	  xzr, [x2, #FPSIMD_CONTEXT_MAGIC_OFFSET]
	  str	  xzr, [x2, #FPSIMD_CONTEXT_SIZE_OFFSET]
	
	  /* Grab the signal mask */
	  /* rt_sigprocmask (SIG_BLOCK, NULL, &ucp->uc_sigmask, _NSIG8) */
	  add	  x2, x0, #UCONTEXT_SIGMASK_OFFSET
	  mov	  x0, #0  /* SIG_BLOCK */
	  mov	  x1, #0  /* NULL */
	  mov	  x3, #(_NSIG / 8)
	  mov	  x8, #__NR_rt_sigprocmask
	  svc	  0
	
	  /* Return x0 for success */
	  mov	  x0, 0
	  ret
#endif
}

#define getcontext(x)   breakpad_getcontext(x)

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#endif  // __BIONIC_UCONTEXT_H

#endif  // GOOGLE_BREAKPAD_COMMON_ANDROID_INCLUDE_UCONTEXT_H
