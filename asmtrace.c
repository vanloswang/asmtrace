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
#include <getopt.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "asmtrace.h"


/* Global variables */
struct config cfg;


/* Local routines */
static pid_t traceme(char **);


/*
 * Fork the process to trace.
 * Returns the PID of the process, on success, -1 on error.
 */
pid_t
traceme(char *argv[])
{
	pid_t pid;

	if ( (pid = fork()) < 0) {
		err_errno("fork failed");
		return(-1);
	}

	/* Wait for parent to attach */
	if (pid == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
			err_errnox("Failed to ptrace myself");

		execvp(argv[0], argv);
		err_errno("Failed to run target program \"%s\"", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (waitpid(pid, NULL, 0) == -1) {
		err_errno("Failed to wait for child process");
		return(-1);
	}

	return(pid);
}

void
usage(const char *pname)
{
	printf("Assembly instruction tracer - <pocpon@fuzzpoint.com>\n");
	printf("Usage: %s [Option(s)] -- <program> [<arg> ...]\n", pname);
	printf("Options:\n");
	printf("  -a --att           - AT&T syntax [default]\n");
	printf("  -i --intel         - Intel syntax\n");
	printf("  -p --pid <pid>     - Attach to PID\n"); 
	printf("  -s --stack <words> - Number of stack-words to print on crash\n");
	printf("  -v --verbose       - Verbose, repeat to increase\n");

	exit(EXIT_FAILURE);
}

const struct option longopts[] =
{
    {"verbose", 0, NULL, 'v'},
    {"att", 0, NULL, 'a'},
    {"intel", 0, NULL, 'i'},
    {"pid", 1, NULL, 'p'},
    {"stack", 1, NULL, 's'},
    {NULL, 0, NULL, 0}
};


int
main(int argc, char *argv[])
{
	pid_t pid = 0;
	int progidx;
	int longindex;
	int i;

	if ((argv[1] == NULL) || (argc <= 1))
		usage(argv[0]);

	/* Default values */
#ifdef __x86_64__
	cfg.mode = 64;
#else
	cfg.mode = 32;
#endif

	cfg.syntax = UD_SYN_ATT;
	cfg.verbose = 0;
	cfg.stack_words = 12;

	/* Find index of program to run in argument array */
	progidx = argc - 1;
	while ((argv[progidx][0] == '-') && progidx > 0)
		progidx--;

	while ( (optind < progidx) && 
			(i = getopt_long(argc, argv, "viap:s:", 
				longopts, &longindex)) != -1) {
		switch (i) {
			case 'v': cfg.verbose++; break;
			case 'a': cfg.syntax = UD_SYN_ATT; break;
			case 'i': cfg.syntax = UD_SYN_INTEL; break;
			case 'p': pid = atoi(optarg); break;
			case 's': cfg.stack_words = strtoul(optarg, NULL, 0); break;
			default:
				usage(argv[0]);
				break;
		}
	}

	if (optind < progidx)
		progidx = optind;

	if (argv[progidx] == NULL)
		usage(argv[0]);

	/* Init disassemble library */
	ud_init(&cfg.ud_obj);
	ud_set_mode(&cfg.ud_obj, cfg.mode);
	ud_set_syntax(&cfg.ud_obj, cfg.syntax);


	if (pid != 0) {
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1)
			err_errnox("Failed to attach to target process");
	}
	else if ( (pid = traceme(&argv[progidx])) < 0)
		exit(EXIT_FAILURE);

	trace(pid);
	exit(EXIT_SUCCESS);
}
