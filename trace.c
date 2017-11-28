/*
 *  Copyright (c) 2004 Claes M. Nyberg <pocpon@fuzzpoint.com>
 *  All rights reserved, all wrongs reversed.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. The name of author may not be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *  AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 *  THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include "asmtrace.h"

/* Global variables */
extern struct config cfg;


/*
 * Trace process.
 * Returns 0 on success, -1 on error.
 */
int
trace(pid_t pid)
{
	enum __ptrace_request step;

	if (cfg.verbose) 
		step = PTRACE_SINGLESTEP;
	else
		step = PTRACE_CONT;

	for (;;) {
		int status;

		if (cfg.verbose) {
			if (disasm(pid, 0) == -1) {
				err("Failed to disassemble instruction\n");
				return(-1);
			}
		}

		/* Step to next instruction or process termination */
		if (ptrace(step, pid, NULL, NULL) == -1) {
			err_errno("ptrace step/continue failed");
			return(-1);
		}
		
		/* Wait for process */
		if (waitpid(pid, &status, 0) == -1) {
			err_errno("Failed to wait for process");
			return(-1);
		}

#ifdef __x86_64__

		/* Child stopped (ignore SIGTRAP) */
		if ( WIFSTOPPED(status)) {
			cfg.verbose = 10;
			printf("\n+++\n");
			disasm(pid, 1);
			printf("--- Signal %u ---\n", WSTOPSIG(status));
			printf("+++ Killed by SIGNAL %u +++\n", WSTOPSIG(status));
			break;
		}
#else
		/* Child stopped (ignore SIGTRAP) */
		if ( (WIFSTOPPED(status)) && (WSTOPSIG(status) != SIGTRAP)) {
			cfg.verbose = 10;
			printf("\n+++\n");
			disasm(pid, 1);
			printf("--- Signal %u ---\n", WSTOPSIG(status));
			printf("+++ Killed by SIGNAL %u +++\n", WSTOPSIG(status));
			break;
		}
#endif
		/* Child exited */
		if (WIFEXITED(status)) {
			printf("--- exit with code %u ---\n", WEXITSTATUS(status));
			break;
		}
	}

	return(0);	
}
