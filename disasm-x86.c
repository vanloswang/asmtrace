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

#ifndef __x86_64__

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

	ud_set_pc(&cfg.ud_obj, regs.eip);
	pc = regs.eip;
	pc_pid = pid;

	ud_set_input_hook(&cfg.ud_obj, read_text_byte);
	ud_set_pc(&cfg.ud_obj, regs.eip);
	ud_disassemble(&cfg.ud_obj);
	asm_ins = ud_insn_asm(&cfg.ud_obj);

	verbose(1, "0x%08lx    %s\n", regs.eip, asm_ins[0] == '\0' ? "??" : asm_ins);

	verbose(2, "  Registers:\n");
	verbose(2, "    eax: 0x%08x\tesi: 0x%08x\n", regs.eax, regs.esi);
	verbose(2, "    ebx: 0x%08x\tedi: 0x%08x\n", regs.ebx, regs.edi);
	verbose(2, "    ecx: 0x%08x\tebp: 0x%08x\n", regs.ecx, regs.ebp);
	verbose(2, "    edx: 0x%08x\tesp: 0x%08x\n", regs.edx, regs.esp);
	verbose(2, "    eip: 0x%08x\teflags: 0x%08x\n", regs.eip, regs.eflags);
	verbose(2, "\n");
	verbose(4, "  Flags:\n");
	verbose(4, "    RF    Resume ................. %d\n", (regs.eflags >> 0x11) & 0x1);
	verbose(4, "    VM    Virtual 8086 ........... %d\n", (regs.eflags >> 0x10) & 0x1);
	verbose(4, "    NT    Nested task ............ %d\n", (regs.eflags >> 0xe) & 0x1);
	verbose(4, "    IOPL  I/O privilege level .... %d\n", (regs.eflags >> 0xc) & 0x1);
	verbose(4, "    OF    Overflow ............... %d\n", (regs.eflags >> 0xb) & 0x1);
	verbose(4, "    DF    Direction .............. %d\n", (regs.eflags >> 0xa) & 0x1);
	verbose(4, "    IF    Enable interrupt ....... %d\n", (regs.eflags >> 0x9) & 0x1);
	verbose(4, "    TF    Trap ................... %d\n", (regs.eflags >> 0x8) & 0x1);
	verbose(4, "    SF    Sign ................... %d\n", (regs.eflags >> 0x7) & 0x1);
	verbose(4, "    ZF    Zero ................... %d\n", (regs.eflags >> 0x6) & 0x1);
	verbose(4, "    AF    Auxiliary carry ........ %d\n", (regs.eflags >> 0x4) & 0x1);
	verbose(4, "    PF    Parity ................. %d\n", (regs.eflags >> 0x2) & 0x1);
	verbose(4, "    CF    Carry .................. %d\n", (regs.eflags >> 0x1) & 0x1);
	verbose(4, "\n");

	if (print_stack) {
		unsigned int value1;
		unsigned int value2;
		unsigned int esp;
		unsigned int i;

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
			esp = regs.esp - (cfg.stack_words/3)*sizeof(int);
	
		verbose(5, "  Stack Dump:\n");
		for (i=0; i<cfg.stack_words; i++) {
			
			value1 = ptrace(PTRACE_PEEKTEXT, pid, esp+i*sizeof(int), NULL);
			if (errno)
				break;
			
			value2 = ptrace(PTRACE_PEEKTEXT, pid, value1, NULL);
			if (errno) {
				verbose(5, "    0x%08x:  0x%08x                ", 
					esp+i*sizeof(int), value1);

				verbose(5, "%c", BYTETABLE[(value1 >> 0) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 8) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 16) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value1 >> 24) & 0xff]);
			}
			else {
				verbose(5, "    0x%08x:  0x%08x -> 0x%08x  ", 
					esp+i*sizeof(int), value1, value2);

				verbose(5, "%c", BYTETABLE[(value2 >> 0) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value2 >> 8) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value2 >> 16) & 0xff]);
				verbose(5, "%c", BYTETABLE[(value2 >> 24) & 0xff]);
			}

			if ( (esp+i*sizeof(int)) == regs.esp)
				verbose(5, "    <-[esp]");
			verbose(5, "\n");
		}
		verbose(5, "\n");
	}

	#undef BYTETABLE	
	return(0);	
}

#endif /* not __x86_64__ */
