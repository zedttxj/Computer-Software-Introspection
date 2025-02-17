# The Patch Directive in Reverse Engineering

In this level of the **[pwn.college CSE365 Reverse Engineering Course](https://pwn.college/cse365-f2024/reverse-engineering/)**, you are introduced to advanced functionality using the **Patch Directive**. Unlike previous challenges, where you had to manually specify all pixels for creating the images, the **Patch Directive** allows for much more efficient and flexible image creation. 

## Challenge Overview

Support for different directives allow fairly advanced cIMG functionality. For example, you previously created the images you needed by specifying all of the pixels explicitly. However, with the advanced functionality added in this level, that is no longer necessary! Consequently, the challenge will not give you the flag if you use too many bytes to make the right image. Good luck.

Approach Suggestion: This level will require you to create a cimage with multiple directives in one file. Some hopefully-useful suggestions:

- Your first several attempts at this will likely result in an error message. Do not simply guess at how to fix this error message! Instead, use a combination of a graphical reversing tool and a debugger (gdb) to actually understand which check is failing, and adjust your input to avoid failing this check.
- Writing your cimage by hand will be very error-prone. Consider creating a Python script to generate cimages. Your script should somewhat mirror the parser library, with a function to generate the cimage header and functions for every directive that you want to support. This will make your life MUCH easier in this and future levels.

## My Approach
# Analysis of `main` Function in `/challenge.cimg`

In this section, we will analyze the `main` function in the `/challenge.cimg` file, which is the primary program responsible for processing the `.cimg` file. The analysis begins with the disassembly of the `main` function using **GDB**.

*GDB Disassembly Output*

```
(gdb) disass main
Dump of assembler code for function main:
   0x00000000004012a4 <+0>:     endbr64
   0x00000000004012a8 <+4>:     push   %r15
   0x00000000004012aa <+6>:     xorps  %xmm0,%xmm0
   0x00000000004012ad <+9>:     push   %r14
   0x00000000004012af <+11>:    push   %r13
   0x00000000004012b1 <+13>:    push   %r12
   0x00000000004012b3 <+15>:    push   %rbp
   0x00000000004012b4 <+16>:    push   %rbx
   0x00000000004012b5 <+17>:    sub    $0x38,%rsp
   0x00000000004012b9 <+21>:    mov    %fs:0x28,%rax
   0x00000000004012c2 <+30>:    mov    %rax,0x28(%rsp)
   0x00000000004012c7 <+35>:    xor    %eax,%eax
   0x00000000004012c9 <+37>:    dec    %edi
   0x00000000004012cb <+39>:    movups %xmm0,0x10(%rsp)
   0x00000000004012d0 <+44>:    movq   $0x0,0x20(%rsp)
   0x00000000004012d9 <+53>:    jle    0x40132a <main+134>
   0x00000000004012db <+55>:    mov    0x8(%rsi),%rbp
   0x00000000004012df <+59>:    or     $0xffffffffffffffff,%rcx
   0x00000000004012e3 <+63>:    lea    0xf3a(%rip),%rsi        # 0x402224
   0x00000000004012ea <+70>:    mov    %rbp,%rdi
   0x00000000004012ed <+73>:    repnz scas %es:(%rdi),%al
   0x00000000004012ef <+75>:    not    %rcx
   0x00000000004012f2 <+78>:    lea    -0x6(%rbp,%rcx,1),%rdi
   0x00000000004012f7 <+83>:    call   0x4011f0 <strcmp@plt>
   0x00000000004012fc <+88>:    test   %eax,%eax
   0x00000000004012fe <+90>:    je     0x401315 <main+113>
   0x0000000000401300 <+92>:    lea    0xf23(%rip),%rsi        # 0x40222a
   0x0000000000401307 <+99>:    mov    $0x1,%edi
--Type <RET> for more, q to quit, c to continue without paging--c
   0x000000000040130c <+104>:   xor    %eax,%eax
   0x000000000040130e <+106>:   call   0x401210 <__printf_chk@plt>
   0x0000000000401313 <+111>:   jmp    0x40135f <main+187>
   0x0000000000401315 <+113>:   xor    %esi,%esi
   0x0000000000401317 <+115>:   mov    %rbp,%rdi
   0x000000000040131a <+118>:   xor    %eax,%eax
   0x000000000040131c <+120>:   call   0x401230 <open@plt>
   0x0000000000401321 <+125>:   xor    %esi,%esi
   0x0000000000401323 <+127>:   mov    %eax,%edi
   0x0000000000401325 <+129>:   call   0x4011a0 <dup2@plt>
   0x000000000040132a <+134>:   lea    0x10(%rsp),%rbx
   0x000000000040132f <+139>:   or     $0xffffffff,%r8d
   0x0000000000401333 <+143>:   xor    %edi,%edi
   0x0000000000401335 <+145>:   mov    $0xc,%edx
   0x000000000040133a <+150>:   lea    0xf0d(%rip),%rcx        # 0x40224e
   0x0000000000401341 <+157>:   mov    %rbx,%rsi
   0x0000000000401344 <+160>:   call   0x40167b <read_exact>
   0x0000000000401349 <+165>:   cmpl   $0x474d4963,0x10(%rsp)
   0x0000000000401351 <+173>:   je     0x401367 <main+195>
   0x0000000000401353 <+175>:   lea    0xf17(%rip),%rdi        # 0x402271
   0x000000000040135a <+182>:   call   0x401170 <puts@plt>
   0x000000000040135f <+187>:   or     $0xffffffff,%edi
   0x0000000000401362 <+190>:   call   0x401240 <exit@plt>
   0x0000000000401367 <+195>:   cmpw   $0x3,0x14(%rsp)
   0x000000000040136d <+201>:   lea    0xf1a(%rip),%rdi        # 0x40228e
   0x0000000000401374 <+208>:   jne    0x40135a <main+182>
   0x0000000000401376 <+210>:   mov    %rbx,%rdi
   0x0000000000401379 <+213>:   lea    0xe(%rsp),%rbp
   0x000000000040137e <+218>:   call   0x401a72 <initialize_framebuffer>
   0x0000000000401383 <+223>:   mov    0x18(%rsp),%eax
   0x0000000000401387 <+227>:   lea    -0x1(%rax),%edx
   0x000000000040138a <+230>:   mov    %edx,0x18(%rsp)
   0x000000000040138e <+234>:   test   %eax,%eax
   0x0000000000401390 <+236>:   je     0x4013f0 <main+332>
   0x0000000000401392 <+238>:   lea    0xf11(%rip),%rcx        # 0x4022aa
   0x0000000000401399 <+245>:   or     $0xffffffff,%r8d
   0x000000000040139d <+249>:   mov    %rbp,%rsi
   0x00000000004013a0 <+252>:   xor    %edi,%edi
   0x00000000004013a2 <+254>:   mov    $0x2,%edx
   0x00000000004013a7 <+259>:   call   0x40167b <read_exact>
   0x00000000004013ac <+264>:   movzwl 0xe(%rsp),%ecx
   0x00000000004013b1 <+269>:   cmp    $0x1,%cx
   0x00000000004013b5 <+273>:   je     0x4013c7 <main+291>
   0x00000000004013b7 <+275>:   cmp    $0x2,%cx
   0x00000000004013bb <+279>:   jne    0x4013d1 <main+301>
   0x00000000004013bd <+281>:   mov    %rbx,%rdi
   0x00000000004013c0 <+284>:   call   0x40185d <handle_2>
   0x00000000004013c5 <+289>:   jmp    0x401383 <main+223>
   0x00000000004013c7 <+291>:   mov    %rbx,%rdi
   0x00000000004013ca <+294>:   call   0x4016da <handle_1>
   0x00000000004013cf <+299>:   jmp    0x401383 <main+223>
   0x00000000004013d1 <+301>:   mov    0xd9c8(%rip),%rdi        # 0x40eda0 <stderr@@GLIBC_2.2.5>
   0x00000000004013d8 <+308>:   lea    0xef2(%rip),%rdx        # 0x4022d1
   0x00000000004013df <+315>:   mov    $0x1,%esi
   0x00000000004013e4 <+320>:   xor    %eax,%eax
   0x00000000004013e6 <+322>:   call   0x401250 <__fprintf_chk@plt>
   0x00000000004013eb <+327>:   jmp    0x40135f <main+187>
   0x00000000004013f0 <+332>:   mov    0x20(%rsp),%rdi
   0x00000000004013f5 <+337>:   xor    %ebx,%ebx
   0x00000000004013f7 <+339>:   lea    0x2c22(%rip),%r12        # 0x404020 <desired_output>
   0x00000000004013fe <+346>:   call   0x401170 <puts@plt>
   0x0000000000401403 <+351>:   mov    0x1c(%rsp),%r14d
   0x0000000000401408 <+356>:   mov    0x20(%rsp),%r13
   0x000000000040140d <+361>:   cmp    $0x738,%r14d
   0x0000000000401414 <+368>:   sete   %bl
   0x0000000000401417 <+371>:   xor    %ebp,%ebp
   0x0000000000401419 <+373>:   xor    %r15d,%r15d
   0x000000000040141c <+376>:   cmp    %ebp,%r14d
   0x000000000040141f <+379>:   jbe    0x401460 <main+444>
   0x0000000000401421 <+381>:   cmp    $0x738,%ebp
   0x0000000000401427 <+387>:   je     0x401460 <main+444>
   0x0000000000401429 <+389>:   mov    0x13(%r13),%al
   0x000000000040142d <+393>:   cmp    0x13(%r12),%al
   0x0000000000401432 <+398>:   cmovne %r15d,%ebx
   0x0000000000401436 <+402>:   cmp    $0x20,%al
   0x0000000000401438 <+404>:   je     0x401454 <main+432>
   0x000000000040143a <+406>:   cmp    $0xa,%al
   0x000000000040143c <+408>:   je     0x401454 <main+432>
   0x000000000040143e <+410>:   mov    $0x18,%edx
   0x0000000000401443 <+415>:   mov    %r12,%rsi
   0x0000000000401446 <+418>:   mov    %r13,%rdi
   0x0000000000401449 <+421>:   call   0x4011e0 <memcmp@plt>
   0x000000000040144e <+426>:   test   %eax,%eax
   0x0000000000401450 <+428>:   cmovne %r15d,%ebx
   0x0000000000401454 <+432>:   inc    %ebp
   0x0000000000401456 <+434>:   add    $0x18,%r13
   0x000000000040145a <+438>:   add    $0x18,%r12
   0x000000000040145e <+442>:   jmp    0x40141c <main+376>
   0x0000000000401460 <+444>:   cmpq   $0x53c,0xd945(%rip)        # 0x40edb0 <total_data>
   0x000000000040146b <+455>:   ja     0x401479 <main+469>
   0x000000000040146d <+457>:   and    $0x1,%bl
   0x0000000000401470 <+460>:   je     0x401479 <main+469>
   0x0000000000401472 <+462>:   xor    %eax,%eax
   0x0000000000401474 <+464>:   call   0x401586 <win>
   0x0000000000401479 <+469>:   mov    0x28(%rsp),%rax
   0x000000000040147e <+474>:   xor    %fs:0x28,%rax
   0x0000000000401487 <+483>:   je     0x40148e <main+490>
   0x0000000000401489 <+485>:   call   0x401190 <__stack_chk_fail@plt>
   0x000000000040148e <+490>:   add    $0x38,%rsp
   0x0000000000401492 <+494>:   xor    %eax,%eax
   0x0000000000401494 <+496>:   pop    %rbx
   0x0000000000401495 <+497>:   pop    %rbp
   0x0000000000401496 <+498>:   pop    %r12
   0x0000000000401498 <+500>:   pop    %r13
   0x000000000040149a <+502>:   pop    %r14
   0x000000000040149c <+504>:   pop    %r15
   0x000000000040149e <+506>:   ret
End of assembler dump.
```
I wanna point out some noticeable functions and variables:

**`__printf_chk@plt`**:
This prints error message (put in `rsi` register, the 2nd parameter) and then exit the program. For example:
```
0x00000000004013d1 <+301>:   mov    0xd9c8(%rip),%rdi        # 0x40eda0 <stderr@@GLIBC_2.2.5>
   0x00000000004013d8 <+308>:   lea    0xef2(%rip),%rdx        # 0x4022d1
   0x00000000004013df <+315>:   mov    $0x1,%esi
   0x00000000004013e4 <+320>:   xor    %eax,%eax
   0x00000000004013e6 <+322>:   call   0x401250 <__fprintf_chk@plt>
```
The error message is at 0x4022d1, by using `x/1s 0x4022d1`, we can check the error message and figure out the functionality of the code above it:
```
(gdb) x/1s 0x4022d1
0x4022d1:       "ERROR: invalid directive_code %ux\n"
```

**`read_exact`**:
This read exact number of bytes (put in rdx register, the 3rd parameter) from our input and put it into address value placed in rsi register (2nd parameter). For example:
```
   0x000000000040132a <+134>:   lea    0x10(%rsp),%rbx
   0x000000000040132f <+139>:   or     $0xffffffff,%r8d
   0x0000000000401333 <+143>:   xor    %edi,%edi
   0x0000000000401335 <+145>:   mov    $0xc,%edx
   0x000000000040133a <+150>:   lea    0xf0d(%rip),%rcx        # 0x40224e
   0x0000000000401341 <+157>:   mov    %rbx,%rsi
   0x0000000000401344 <+160>:   call   0x40167b <read_exact>
```
Here, there are 12 bytes read from our input and put in the memory at $rsp+0x10

**`desired_output`**:
Typically, this is hard-written in the program and will be used to compared (using memcmp@plt from C library) with our actual output. It looks like this:
```
(gdb) x/1s 0x404020
0x404020 <desired_output>:      "\033[38;2;255;255;255m.\033[0m\033[38;2;255;255;255m-\033[0m\033[38;2;255;255;255m-\033[0m\033[38;2;255;255;255m-\033[0m\033[38;2;255;255;255m-\033[0m\033[38;2;255;255;255m-\033[0m\033[38;2;255;255;255m-\033[0m\033[38;2;255;255;255m-\033[0m\033[38;2;2"...
```
This is a typical representation of terminal pixel where you see the part 255,255,255 represent the pixel color right after the letter `m` represent the actual character.
To extract this output to a file, we can use command `dump binary memory dumpfile.bin 0x404020 0x404020+0x738*24`
where 0x738 is the number of the pixels and 24 is the information of each pixel:
```
(gdb) dump binary memory dumpfile.bin 0x404020 0x404020+0x738*24
(gdb) shell cat dumpfile.bin
.--------------------------------------------------------------------------.
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                              ___   __  __    ____                        |
|                        ___  |_ _| |  \/  |  / ___|                       |
|                       / __|  | |  | |\/| | | |  _                        |
|                      | (__   | |  | |  | | | |_| |                       |
|                       \___| |___| |_|  |_|  \____|                       |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
|                                                                          |
'--------------------------------------------------------------------------'
(gdb) shell xxd dumpfile.bin | head
00000000: 1b5b 3338 3b32 3b32 3535 3b32 3535 3b32  .[38;2;255;255;2
00000010: 3535 6d2e 1b5b 306d 1b5b 3338 3b32 3b32  55m..[0m.[38;2;2
00000020: 3535 3b32 3535 3b32 3535 6d2d 1b5b 306d  55;255;255m-.[0m
00000030: 1b5b 3338 3b32 3b32 3535 3b32 3535 3b32  .[38;2;255;255;2
00000040: 3535 6d2d 1b5b 306d 1b5b 3338 3b32 3b32  55m-.[0m.[38;2;2
00000050: 3535 3b32 3535 3b32 3535 6d2d 1b5b 306d  55;255;255m-.[0m
00000060: 1b5b 3338 3b32 3b32 3535 3b32 3535 3b32  .[38;2;255;255;2
00000070: 3535 6d2d 1b5b 306d 1b5b 3338 3b32 3b32  55m-.[0m.[38;2;2
00000080: 3535 3b32 3535 3b32 3535 6d2d 1b5b 306d  55;255;255m-.[0m
00000090: 1b5b 3338 3b32 3b32 3535 3b32 3535 3b32  .[38;2;255;255;2
```
**`total_data`**
It represents the actual size of our input. It's only used once at `main+444` to limit the number of input bytes:
```
0x0000000000401460 <+444>:   cmpq   $0x53c,0xd945(%rip)        # 0x40edb0 <total_data>
```
If our input exceeded 0x53c bytes, the program will exit normally without triggering the `win` function, which is our goal. I figured it out by print the total_data using `p 0x40edb0`

I start the program using `start output.cimg` where my output.cimg is my cimg file

#### from `main+63` to `main+90`
I used `x/1s 0x402224` and saw the message:
```
(gdb) x/1s 0x402224
0x402224:       ".cimg"
```
The string ".cimg" (in 2nd parameter or rsi register) is compared with another string. I assume that the other string is the last 4 characters of the name of the file you put in (in this case is `output.cimg`). The `test %eax, %eax` checks if the value of strcmp is 0, then jump if it's 0.
