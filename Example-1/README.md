# The Patch Directive in Reverse Engineering

In this level of the **[pwn.college CSE365 Reverse Engineering Course](https://pwn.college/cse365-f2024/reverse-engineering/)**, you are introduced to advanced functionality using the **Patch Directive**. Unlike previous challenges, where you had to manually specify all pixels for creating the images, the **Patch Directive** allows for much more efficient and flexible image creation. 

## Challenge Overview

Support for different directives allow fairly advanced cIMG functionality. For example, you previously created the images you needed by specifying all of the pixels explicitly. However, with the advanced functionality added in this level, that is no longer necessary! Consequently, the challenge will not give you the flag if you use too many bytes to make the right image. Good luck.

Approach Suggestion: This level will require you to create a cimage with multiple directives in one file. Some hopefully-useful suggestions:

- Your first several attempts at this will likely result in an error message. Do not simply guess at how to fix this error message! Instead, use a combination of a graphical reversing tool and a debugger (gdb) to actually understand which check is failing, and adjust your input to avoid failing this check.
- Writing your cimage by hand will be very error-prone. Consider creating a Python script to generate cimages. Your script should somewhat mirror the parser library, with a function to generate the cimage header and functions for every directive that you want to support. This will make your life MUCH easier in this and future levels.

# My Approach
## Analysis of `main` Function in `/challenge.cimg`

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

**`__printf_chk@plt` or `__fprintf_chk@plt`**:
This prints error message (put in `rsi` register, the 2nd parameter) and then exit the program. For example:
```
0x00000000004013d1 <+301>:   mov    0xd9c8(%rip),%rdi        # 0x40eda0 <stderr@@GLIBC_2.2.5>
   0x00000000004013d8 <+308>:   lea    0xef2(%rip),%rdx        # 0x4022d1
   0x00000000004013df <+315>:   mov    $0x1,%esi
   0x00000000004013e4 <+320>:   xor    %eax,%eax
   0x00000000004013e6 <+322>:   call   0x401250 <__fprintf_chk@plt>
```
The error message is at the address where `rdx` register holds. By using `x/1s 0x4022d1`, we can check the error message and figure out the functionality of the code above it:
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
If our input exceeded 0x53c bytes, the program will exit normally without triggering the `win` function. Our goal is to triggering the `win` function. I figured out this fact by printing the total_data using `p 0x40edb0`

### Running the Program

I start the program using `start output.cimg` where my output.cimg is my cimg file

#### from `main+63` to `main+90`
I used `x/1s 0x402224` and saw the message:
```
(gdb) x/1s 0x402224
0x402224:       ".cimg"
```
The string ".cimg" (in 2nd parameter or rsi register) is compared with another string. I assume that the other string is the last 4 characters of the name of the file you put in (in this case is `output.cimg`). The `test %eax, %eax` checks if the value of strcmp is 0, then jump to `main+113` if it's 0.

#### from `main+113` to `main+129`
It opens the file that the `rbp` register still holds (the file's name in this case is my `output.cimg`).

#### from `main+145` to `main+190`
The instruction `0x0000000000401335 <+145>:   mov    $0xc,%edx` moves the value 0xc (which is 12 in decimal) into `edx` register, which is the 3rd parameter if we call a function. In this case, we call read_exact. Reminds you that read_exact use 3rd paramenter as a size of the input it will takes. In conclusion, the program will read 12 bytes and put it at the address `$rsp+0x10` (not deferencing). After that, it compares the first 4 bytes of those 12 bytes with 0x474d4963, which is also the string value "cIMG":
```
(gdb) p (char[4])0x474d4963
$4 = "cIMG"
```
If the value from our input is equal to "cIMG", the program won't exit (the exiting process starts from `main+175` to `main+190`)

#### from `main+195` to `main+208`
The instruction `0x0000000000401367 <+195>:   cmpw   $0x3,0x14(%rsp)` compare a word (2 bytes) from the 5th byte of our 12-bytes input earlier with 0x3 (our 12-bytes input starts at `$rsp+0x10`). If it's not equal, it will come back to `main+182` and start the exiting process.

#### from `main+223` to `main+327` (the loop)
It moves 4 bytes starting at the 8th byte from our 12-bytes input earlier into `eax` register. Then, it starts to perform a loop that uses `eax` as its iterator and decrease it by 1 every 1 loop until it's equal to 0 (you can see that fact at instruction `main+234` and `main+236` where `main+332` is the end of the loop. Inside the loop, it reads 2 bytes (from `main+254` to `main+259`) and then put them at the address in `rbp` register, which is also holding the address of `$rsp+0xe`. If the value is 0x1, it calls `handle_1` function. If it's 0x2, it calls `handle_2` function. If it's other values, it calls `__fprintf_chk@plt` and print the error message stored at 0x4022d1:
```
(gdb) x/1s 0x4022d1
0x4022d1:       "ERROR: invalid directive_code %ux\n"
```
After calling the function, it will iterate again (`0x00000000004013eb <+327>:   jmp    0x40135f <main+187>`)
The function `handle_1` and function `handle_2` have different ways to process our data and we will analyze it later. After this loop, our `.cimg` file is completedly processed.

#### from `main+332` to `main+368`
The total size of our input image is put in `$rsp+0x1c`. To adjust this size, we can adjust the width of the image (the 7-th byte from the 12-bytes input earlier) and the height of the image (the 8-th byte from the 12-bytes input earlier). I figured this out by first seeing where the `$rsp+0x1c` changes its value. Adding watchpoint like this can help the process of finding faster: `(gdb) watch *(long *)($rsp+0x1c)`. This instruction would calculate the value of `$rsp+0x1c`, extract 8 bytes (which explains why I use long here) and dereferrence it. However, every time some functions are called, there's a high chance that the stack pointer register (`rsp`) has changed, leading to triggering the breakpoint a lot of times. The better way to do this is to put a watchpoint on a specific value:
```
(gdb) start output.cimg
Temporary breakpoint 14 at 0x4012a4
Starting program: /challenge/cimg output.cimg

Temporary breakpoint 14, 0x00000000004012a4 in main ()
(gdb) break *main+53
Breakpoint 15 at 0x4012d9
(gdb) c
Continuing.

Breakpoint 15, 0x00000000004012d9 in main ()
(gdb) p $rsp
$1 = (void *) 0x7ffe78831bc0
(gdb) watch *(long *)(0x7ffe78831bc0+0x1c)
Hardware watchpoint 16: *(long *)(0x7ffe78831bc0+0x1c)
(gdb) c
Continuing.

Breakpoint 8, 0x000000000040137e in main ()
(gdb) c
Continuing.

Hardware watchpoint 16: *(long *)(0x7ffe78831bc0+0x1c)

Old value = 0
New value = 1000
0x0000000000401aa5 in initialize_framebuffer ()
```
Here, the value is changed to 1848, which is my actual size of my image size (I put my heigh as 50 and my width as 20 for example) and also the same number that will be compared at instruction `main+361`. To delete the watch point, you can use command `info b` to show all the breakpoints and `delete <id of the breakpoint>` to delete that breakpoint. Another way to track your value is to use these 3 debugging instructions simultaneously: `ni` (which run 1 instruction at a time), `where` (show where's the current `rip` register is, which is also where our instruction pointer at), and `x/1x $rsp+0x1c` (print the value at `$rsp+0x1c`). Instead of typing 3 lines of debugging instructions, you can define another instruction and reuse it like this (here I define `co`):
```
(gdb) define co
Redefine command "co"? (y or n) y
Type commands for definition of "co".
End with a line saying just "end".
>ni
>where
>x/1x $rsp+0x1c
>end
(gdb) co
0x0000000000401abc in initialize_framebuffer ()
#0  0x0000000000401abc in initialize_framebuffer ()
#1  0x0000000000401383 in main ()
0x7ffe78831b8c: 0x00000000
(gdb)
0x0000000000401ad2 in initialize_framebuffer ()
#0  0x0000000000401ad2 in initialize_framebuffer ()
#1  0x0000000000401383 in main ()
0x7ffe78831b8c: 0x00000000
(gdb)
0x0000000000401ad4 in initialize_framebuffer ()
#0  0x0000000000401ad4 in initialize_framebuffer ()
#1  0x0000000000401383 in main ()
0x7ffe78831b8c: 0x00000000
```
After figuring out where the value is changed, I analyzed the function `initialize_framebuffer`. You can also try adjusting the 12-bytes of your `.cimg` input file and see if there's any changes. This will tell us the total of pixels produced by our .cimg is in `$rsp+0x1c`.
Let's continue!
The value in `r14d` (from `$rsp+0x1c`) is compared with 0x738 and the `bl` register is set. If it's equal, `bl` register will be 1. Otherwise, it will be 0. In other words, if our .cimg file produce the same number of pixels (which is 0x738), `bl` is equal to 1.

#### from `main+371` to `main+442`
Another loop! Here, `rbp` register is used as an iterator and will perform the total of `r14d` (the size of our output image produced by our .cimg file) loops. Remember, the `memcmp@plt` compare the value starting from the 1st parameter with the value starting from the 2nd parameter for exact number of bytes (which is represented by the 3rd parameter). You can see that there are 0x18 bytes being compared (which is 24 bytes) each loop since `edx` represents the 3rd parameter: `0x000000000040143e <+410>:   mov    $0x18,%edx`
The value is returned to `eax` after calling a function. The next 2 instructions (`main+426` and `main+428`) moves the value from `r15d` into `ebx` if `eax` is not 0 (which also means the 2 values being compared by `memcmp@plt` function are not equal). This can potentially change the `bl` register since it's the lower 8-bits of the `rbx` register. The 2 instructions `main+434` and `main+438` will shift the pointers 24 bytes forward and compare the next 24 bytes in the next loop.

#### from `main+444` to end
The instruction at `main+444` compare our actual size of our .cimg file by bytes (stored at total_data). If our size exceeds 0x53c, the program will exit normally without triggering the `win` function. The instruction at `main+457` checks if `bl` is equal to 1. If that's the case, the program won't jump and will trigger `win` function. In this case, we would have to keep our number of pixels produced by our .cimg file equal to 0x738

## Analyzing `handle_1` function
Let's disassemble `handle_1`:
```
(gdb) disass handle_1
Dump of assembler code for function handle_1:
   0x00000000004016da <+0>:     endbr64
   0x00000000004016de <+4>:     push   %r15
   0x00000000004016e0 <+6>:     push   %r14
   0x00000000004016e2 <+8>:     push   %r13
   0x00000000004016e4 <+10>:    push   %r12
   0x00000000004016e6 <+12>:    push   %rbp
   0x00000000004016e7 <+13>:    push   %rbx
   0x00000000004016e8 <+14>:    mov    %rdi,%rbx
   0x00000000004016eb <+17>:    sub    $0x48,%rsp
   0x00000000004016ef <+21>:    movzbl 0x6(%rdi),%ebp
   0x00000000004016f3 <+25>:    movzbl 0x7(%rdi),%edx
   0x00000000004016f7 <+29>:    mov    %fs:0x28,%rax
   0x0000000000401700 <+38>:    mov    %rax,0x38(%rsp)
   0x0000000000401705 <+43>:    xor    %eax,%eax
   0x0000000000401707 <+45>:    imul   %edx,%ebp
   0x000000000040170a <+48>:    movslq %ebp,%rbp
   0x000000000040170d <+51>:    shl    $0x2,%rbp
   0x0000000000401711 <+55>:    mov    %rbp,%rdi
   0x0000000000401714 <+58>:    call   0x401200 <malloc@plt>
   0x0000000000401719 <+63>:    test   %rax,%rax
   0x000000000040171c <+66>:    jne    0x40172c <handle_1+82>
   0x000000000040171e <+68>:    lea    0x9ae(%rip),%rdi        # 0x4020d3
   0x0000000000401725 <+75>:    call   0x401170 <puts@plt>
   0x000000000040172a <+80>:    jmp    0x401783 <handle_1+169>
   0x000000000040172c <+82>:    mov    %ebp,%edx
   0x000000000040172e <+84>:    mov    %rax,%rsi
   0x0000000000401731 <+87>:    or     $0xffffffff,%r8d
   0x0000000000401735 <+91>:    xor    %edi,%edi
--Type <RET> for more, q to quit, c to continue without paging--c
   0x0000000000401737 <+93>:    lea    0x9ca(%rip),%rcx        # 0x402108
   0x000000000040173e <+100>:   mov    %rax,%r12
   0x0000000000401741 <+103>:   call   0x40167b <read_exact>
   0x0000000000401746 <+108>:   movzbl 0x7(%rbx),%eax
   0x000000000040174a <+112>:   movzbl 0x6(%rbx),%edx
   0x000000000040174e <+116>:   imul   %eax,%edx
   0x0000000000401751 <+119>:   xor    %eax,%eax
   0x0000000000401753 <+121>:   cmp    %eax,%edx
   0x0000000000401755 <+123>:   jle    0x40178b <handle_1+177>
   0x0000000000401757 <+125>:   movzbl 0x3(%r12,%rax,4),%ecx
   0x000000000040175d <+131>:   inc    %rax
   0x0000000000401760 <+134>:   lea    -0x20(%rcx),%esi
   0x0000000000401763 <+137>:   cmp    $0x5e,%sil
   0x0000000000401767 <+141>:   jbe    0x401753 <handle_1+121>
   0x0000000000401769 <+143>:   mov    0xd630(%rip),%rdi        # 0x40eda0 <stderr@@GLIBC_2.2.5>
   0x0000000000401770 <+150>:   lea    0x9ad(%rip),%rdx        # 0x402124
   0x0000000000401777 <+157>:   mov    $0x1,%esi
   0x000000000040177c <+162>:   xor    %eax,%eax
   0x000000000040177e <+164>:   call   0x401250 <__fprintf_chk@plt>
   0x0000000000401783 <+169>:   or     $0xffffffff,%edi
   0x0000000000401786 <+172>:   call   0x401240 <exit@plt>
   0x000000000040178b <+177>:   xor    %r13d,%r13d
   0x000000000040178e <+180>:   lea    0x1f(%rsp),%r14
   0x0000000000401793 <+185>:   movzbl 0x7(%rbx),%eax
   0x0000000000401797 <+189>:   cmp    %r13d,%eax
   0x000000000040179a <+192>:   jle    0x401839 <handle_1+351>
   0x00000000004017a0 <+198>:   xor    %ebp,%ebp
   0x00000000004017a2 <+200>:   movzbl 0x6(%rbx),%r15d
   0x00000000004017a7 <+205>:   cmp    %ebp,%r15d
   0x00000000004017aa <+208>:   jle    0x401831 <handle_1+343>
   0x00000000004017b0 <+214>:   lea    0x1(%r15),%eax
   0x00000000004017b4 <+218>:   lea    0x99b(%rip),%r8        # 0x402156
   0x00000000004017bb <+225>:   mov    $0x19,%ecx
   0x00000000004017c0 <+230>:   mov    %r14,%rdi
   0x00000000004017c3 <+233>:   imul   %r13d,%eax
   0x00000000004017c7 <+237>:   mov    $0x19,%esi
   0x00000000004017cc <+242>:   mov    %eax,0xc(%rsp)
   0x00000000004017d0 <+246>:   sub    %r13d,%eax
   0x00000000004017d3 <+249>:   add    %ebp,%eax
   0x00000000004017d5 <+251>:   push   %rdx
   0x00000000004017d6 <+252>:   cltq
   0x00000000004017d8 <+254>:   lea    (%r12,%rax,4),%rax
   0x00000000004017dc <+258>:   movzbl 0x3(%rax),%edx
   0x00000000004017e0 <+262>:   push   %rdx
   0x00000000004017e1 <+263>:   movzbl 0x2(%rax),%edx
   0x00000000004017e5 <+267>:   push   %rdx
   0x00000000004017e6 <+268>:   movzbl 0x1(%rax),%edx
   0x00000000004017ea <+272>:   push   %rdx
   0x00000000004017eb <+273>:   movzbl (%rax),%r9d
   0x00000000004017ef <+277>:   mov    $0x1,%edx
   0x00000000004017f4 <+282>:   xor    %eax,%eax
   0x00000000004017f6 <+284>:   call   0x401150 <__snprintf_chk@plt>
   0x00000000004017fb <+289>:   mov    %ebp,%eax
   0x00000000004017fd <+291>:   mov    0x2c(%rsp),%r10d
   0x0000000000401802 <+296>:   movups (%r14),%xmm0
   0x0000000000401806 <+300>:   cltd
   0x0000000000401807 <+301>:   add    $0x20,%rsp
   0x000000000040180b <+305>:   inc    %ebp
   0x000000000040180d <+307>:   idiv   %r15d
   0x0000000000401810 <+310>:   lea    (%rdx,%r10,1),%eax
   0x0000000000401814 <+314>:   xor    %edx,%edx
   0x0000000000401816 <+316>:   divl   0xc(%rbx)
   0x0000000000401819 <+319>:   imul   $0x18,%rdx,%rdx
   0x000000000040181d <+323>:   add    0x10(%rbx),%rdx
   0x0000000000401821 <+327>:   movups %xmm0,(%rdx)
   0x0000000000401824 <+330>:   mov    0x10(%r14),%rax
   0x0000000000401828 <+334>:   mov    %rax,0x10(%rdx)
   0x000000000040182c <+338>:   jmp    0x4017a2 <handle_1+200>
   0x0000000000401831 <+343>:   inc    %r13d
   0x0000000000401834 <+346>:   jmp    0x401793 <handle_1+185>
   0x0000000000401839 <+351>:   mov    0x38(%rsp),%rax
   0x000000000040183e <+356>:   xor    %fs:0x28,%rax
   0x0000000000401847 <+365>:   je     0x40184e <handle_1+372>
   0x0000000000401849 <+367>:   call   0x401190 <__stack_chk_fail@plt>
   0x000000000040184e <+372>:   add    $0x48,%rsp
   0x0000000000401852 <+376>:   pop    %rbx
   0x0000000000401853 <+377>:   pop    %rbp
   0x0000000000401854 <+378>:   pop    %r12
   0x0000000000401856 <+380>:   pop    %r13
   0x0000000000401858 <+382>:   pop    %r14
   0x000000000040185a <+384>:   pop    %r15
   0x000000000040185c <+386>:   ret
End of assembler dump.
```
Remember, instruction `main+291` puts the value of `rbx` into `rdi` (our 1st parameter) and the last time `rbx` was assigned value is in instruction `main+134`. The value `$rsp+0x10` is the address of the first 12-bytes input earlier from our .cimg file. At `handle_1+14`, `rbx` was assigned the same value again. This means `rbx` is currently holding the address of our first 12-bytes input.

#### from `handle_1+21` to `handle_1+51`
The 6th byte (the width) of our first 12-bytes input is put in `ebp` and the 7th byte is put in `edx`. Then, `ebp` is assigned the value `ebp*edx`, which is the total of pixels of our output image at instruction `handle_1+45`. After that, it shifts 2 bytes to the left at instruction `handle_1+51`, meaning quatrupling its size.

#### from `handle_1+55` to `handle_1+84`
It calls the function `malloc@plt` to allocate `rbp` bytes (total of pixels * 4) and puts the address of that memory allocation into `rsi`, preparing for the next instructions

#### from `handle_1+87` to `handle_1+103`
It reads `rbp` bytes and put them into the memory that was allocated earlier. `r12` is now holding the address of that memory.

#### from `handle_1+108` to `handle_1+172`
A loop where it uses `eax` as its iterator and will complete the total of `edx` (which is now representing the number of pixels being processed) loops. Inside the loop, it uses `0x3+r12+rax*4` to extract the last byte of every 4 bytes iterated and then subtract it to 0x20. Then, it compares that value with 0x5e and perform the loop again. In other words, the last byte of every 4 bytes iterated must not be above 0x7e (which is 0x5e+0x20) or else it will exit the program. You can check the message at `0x402124` to confirm it:
```
(gdb) x/1s 0x402124
0x402124:       "ERROR: Invalid character 0x%x in the image data!\n"
```

#### from `handle_1+177` to `handle_1+346`
There are double loops where the outside loop uses `r13d` as its iterator and will complete a number of loops, which is the height of our image in this case. The inside loop uses `ebp` as its iterator and will complete a number of loops, which is the width of our image in this case. From `handle_1+214` to `handle_1+301` is the typical process of printing the pixels to `stdout`. These instructions explain why the last byte of every 4 bytes iterated is the character being represented and the first 3 bytes of every 4 bytes iterated is the pixel's color. These must produce the output image that matchs the `desired_output`.
