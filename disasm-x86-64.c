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

#ifdef __x86_64__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include "asmtrace.h"


/* Global variables */
struct config cfg;


/* Current process counter value */
static volatile int pc;
static volatile pid_t pc_pid;

/*
 * Read a single byte from text
 * Returns the byte on success, UD_EOI on end of input.
 */
int
read_text_byte()
{
	int word;
	unsigned char *pt;

	word = ptrace(PTRACE_PEEKTEXT, pc_pid, pc, NULL);
	pc++;
	pt = (unsigned char *)&word;
	if (errno)
		return(UD_EOI);

	return((int)pt[0]);
}


/*
 * Disassemble current instruction.
 * Returns 0 on success, -1 on error.
 */
int
disasm(pid_t pid, int print_stack)
{
	struct user_regs_struct regs;
	const char *asm_ins;

	if (!cfg.verbose)
		return(0);

	/* Read register values */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
		err_errno("Failed to get register values");
		return(-1);
	}

	ud_set_pc(&cfg.ud_obj, regs.rip);
	pc = regs.rip;
	pc_pid = pid;

	ud_set_input_hook(&cfg.ud_obj, read_text_byte);
	ud_set_pc(&cfg.ud_obj, regs.rip);
	ud_disassemble(&cfg.ud_obj);
	asm_ins = ud_insn_asm(&cfg.ud_obj);

	verbose(1, "0x%016lx    %s\n", regs.rip, asm_ins[0] == '\0' ? "??" : asm_ins);

	verbose(2, "  Registers:\n");
	verbose(2, "    rax: 0x%016lx\n", regs.rax);
	verbose(2, "    rbx: 0x%016lx\n", regs.rbx);
	verbose(2, "    rcx: 0x%016lx\n", regs.rcx);
	verbose(2, "    rdx: 0x%016lx\n", regs.rdx);
	verbose(2, "    rdi: 0x%016lx\n", regs.rdi);
	verbose(2, "    rsi: 0x%016lx\n", regs.rsi);
	verbose(2, "     r8: 0x%016lx\n", regs.r8);
	verbose(2, "     r9: 0x%016lx\n", regs.r9);
	verbose(2, "    r10: 0x%016lx\n", regs.r10);
	verbose(2, "    r11: 0x%016lx\n", regs.r11);
	verbose(2, "    r12: 0x%016lx\n", regs.r12);
	verbose(2, "    r13: 0x%016lx\n", regs.r13);
	verbose(2, "    r14: 0x%016lx\n", regs.r14);
	verbose(2, "    r15: 0x%016lx\n", regs.r15);
	verbose(2, "    rbp: 0x%016lx\n", regs.rbp);
	verbose(2, "    rsp: 0x%016lx\n", regs.rsp);
	verbose(2, "    rip: 0x%016lx\n", regs.rip);

	if (print_stack) {
		unsigned long int value1;
		unsigned long int value2;
		unsigned long int rsp;
		unsigned long int i;

    #define BYTETABLE \
        "................................."\
        "!\"#$%&'()*+,-./0123456789:;<=>?@"\
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"\
        "abcdefghijklmnopqrstuvwxyz{|}~..."\
        "................................."\
        "................................."\
        "................................."\
        "..........................."


		if (cfg.stack_words >= 12)
			rsp = regs.rsp - (cfg.stack_words/3)*sizeof(int);
	
		verbose(5, "  Stack Dump:\n");
		for (i=0; i<cfg.stack_words; i++) {
			
			value1 = ptrace(PTRACE_PEEKTEXT, pid, rsp+i*sizeof(long int), NULL);
			if (errno)
				break;
			
			value2 = ptrace(PTRACE_PEEKTEXT, pid, value1, NULL);
			if (errno) {
				verbose(5, "    0x%016lx:  0x%016lx                        ", 
					rsp+i*sizeof(int), value1);

				verbose(5, "%c", BYTETABLE[(value1 >> 0) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 8) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 16) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 24) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 32) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 40) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 48) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 56) & 0xff]);
			}
			else {
				verbose(5, "    0x%016lx:  0x%016lx -> 0x%016lx  ", 
					rsp+i*sizeof(int), value1, value2);

				verbose(5, "%c", BYTETABLE[(value2 >> 0) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value2 >> 8) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value2 >> 16) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value2 >> 24) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 32) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 40) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 48) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 56) & 0xff]);
			}

			if ( (rsp+i*sizeof(long int)) == regs.rsp)
				verbose(5, "    <-[rsp]");
			verbose(5, "\n");
		}
		verbose(5, "\n");
	}

	#undef BYTETABLE	
	return(0);	
}

#endif /* __x86_64__ */
