Trace x86 and x86-64 aseembly instructions.
Tested on Ubuntu 16 64-bit
run 'make' to build


-=[ Usage
Usage: ./bin-linux/asmtrace-x86 [Option(s)] -- <program> [<arg> ...]
Options:
  -a --att           - AT&T syntax [default]
  -i --intel         - Intel syntax
  -p --pid <pid>     - Attach to PID
  -s --stack <words> - Number of stack-words to print on crash
  -v --verbose       - Verbose, repeat to increase

-=[ Example

$ ./bin-linux/asmtrace-x86 -v ./vuln.32 AAAAAAAAAAAAAAAAAAAAAAAAAAAAA 
0xf7fd9a20    mov %esp, %eax
0xf7fd9a22    call 0xf7fda5c0
0xf7fda5c0    push %ebp
0xf7fda5c1    mov %esp, %ebp
0xf7fda5c3    push %edi
0xf7fda5c4    push %esi
0xf7fda5c5    push %ebx
0xf7fda5c6    call 0xf7ff2769
[...]
0xf7e73a88    test $0x20, %al
0xf7e73a8a    jnz 0xf7e73b70
0xf7e73b70    mov (%ecx), %eax
0xf7e73b72    mov %eax, (%edx)
0xf7e73b74    mov 0x4(%ecx), %ax
0xf7e73b78    mov %ax, 0x4(%edx)
0xf7e73b7c    mov %edi, %eax
0xf7e73b7e    pop %edi
0xf7e73b7f    ret 
0x08048420    add $0x10, %esp
0x08048423    mov $0x0, %eax
0x08048428    leave 
0x08048429    ret 
0x08040041    ret 

+++
0x08040041    ret 
  Registers:
    eax: 0x00000000	esi: 0xf7fa6000
    ebx: 0x00000000	edi: 0xf7fa6000
    ecx: 0xffffd930	ebp: 0x41414141
    edx: 0xffffd6c8	esp: 0xffffd6d0
    eip: 0x08040041	eflags: 0x00010282

  Flags:
    RF    Resume ................. 0
    VM    Virtual 8086 ........... 1
    NT    Nested task ............ 0
    IOPL  I/O privilege level .... 0
    OF    Overflow ............... 0
    DF    Direction .............. 0
    IF    Enable interrupt ....... 1
    TF    Trap ................... 0
    SF    Sign ................... 1
    ZF    Zero ................... 0
    AF    Auxiliary carry ........ 0
    PF    Parity ................. 0
    CF    Carry .................. 1

  Stack Dump:
    0xffffd6c0:  0x41414141                AAAA
    0xffffd6c4:  0x41414141                AAAA
    0xffffd6c8:  0x41414141                AAAA
    0xffffd6cc:  0x08040041                A...
    0xffffd6d0:  0xffffd918 -> 0x41414141  AAAA    <-[esp]
    0xffffd6d4:  0xffffd794 -> 0xffffd90e  ....
    0xffffd6d8:  0xffffd7a0 -> 0xffffd936  6...
    0xffffd6dc:  0x08048481 -> 0xff08838d  ....
    0xffffd6e0:  0xf7fa63dc -> 0xf7fa71e0  .q..
    0xffffd6e4:  0xffffd700 -> 0x00000002  ....
    0xffffd6e8:  0x00000000                ....
    0xffffd6ec:  0xf7e0c637 -> 0x8310c483  ....

--- Signal 11 ---
+++ Killed by SIGNAL 11 +++

