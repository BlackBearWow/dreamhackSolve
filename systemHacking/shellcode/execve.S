;Name: execve.S

mov rax, 0x68732F6E69622F
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 0x3b
syscall	;execve("/bin/sh", null, null)
